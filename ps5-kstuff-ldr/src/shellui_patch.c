#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/user.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "utils.h"

enum { PID_LOOKUP_ERROR = -2, PID_NOT_FOUND = -1 };
#define SHELLUI_EVENT_RETRY_CHECKS 5

#define LOG_PUTS(s)   \
    {                 \
        puts(s);      \
        klog_puts(s); \
    }

#define LOG_PRINTF(s, ...)               \
    {                                    \
        fprintf(stdout, s, __VA_ARGS__); \
        klog_printf(s, __VA_ARGS__);     \
    }

#define LOG_PERROR(s)                                         \
    {                                                         \
        fprintf(stderr, "%s:%d:%s: %s\n", __FILE__, __LINE__, \
                s, strerror(errno));                          \
        klog_printf("%s:%d:%s: %s\n", __FILE__, __LINE__,     \
                    s, strerror(errno));                      \
    }

static unsigned long vmspace_pmap(unsigned long vmspace_kaddr) {
    /*
     * TODO(FW_PORT): verify vmspace->vm_pmap in the new kernel before
     * extending these ranges.  Find kernel functions which load p_vmspace and
     * then address the embedded pmap; confirm pm_pml4/pm_cr3 remain at +0x20.
     * 13.60 vmspace_free and pmap activation paths use vmspace+0x2e8 and load
     * CR3 from vmspace+0x310, confirming pmap+0x28.
     */
    switch (kernel_get_fw_version() >> 16) {
        case 0x100 ... 0x102: return vmspace_kaddr + 0x2C0;
        case 0x105 ... 0x550: return vmspace_kaddr + 0x2E0;
        case 0x600 ... 0x1360: return vmspace_kaddr + 0x2E8;
        default: return 0; // unsupported fw version
    }
}

static unsigned long kernel_get_proc_cr3(int pid, unsigned long *optional_out_kernel_dmap_base) {
    unsigned long proc = kernel_get_proc(pid);
    if (proc == 0) {
        return 0;
    }

    unsigned long vmspace = kernel_getlong(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
    if (vmspace == 0) {
        return 0;
    }

    unsigned long pmap = vmspace_pmap(vmspace);
    if (pmap == 0) {
        return 0;
    }
    unsigned long data[2];
    if (kernel_copyout(pmap + 32, data, sizeof(data))) {
        return 0;
    }

    unsigned long pm_pml4 = data[0];
    unsigned long pm_cr3 = data[1];

    if (optional_out_kernel_dmap_base) {
        *optional_out_kernel_dmap_base = pm_pml4 - pm_cr3;
    }
    return pm_cr3;
}

// from ps5-kstuff/main.c
static uint64_t virt2phys(uintptr_t addr, uint64_t *phys_limit, uint64_t dmap, uint64_t pml) {
    pml &= PG_FRAME;

    for (int i = 39; i >= 12; i -= 9) {
        unsigned long index = (addr >> i) & ((1ull << 9) - 1);
        unsigned long entry_offset = index * sizeof(unsigned long);
        pml = kernel_getlong(dmap + pml + entry_offset);

        if (!(pml & X86_PG_V)) {
            return -1;
        }
        if ((pml & X86_PG_PS) || i == 12) {
            pml &= (1ull << 52) - (1ull << i);
            pml |= addr & ((1ull << i) - 1);
            if (phys_limit) {
                *phys_limit = (pml | ((1ull << i) - 1)) + 1;
            }
            return pml;
        }
        pml &= PG_FRAME;
    }

    __builtin_unreachable();
}

static int phys_copyin(uint64_t vaddr, const void *src, uint64_t sz, uint64_t dmap, uint64_t pml) {
    const char *p_src = src;
    uint64_t phys, phys_end;
    while (sz) {
        phys = virt2phys(vaddr, &phys_end, dmap, pml);
        if (phys == -1)
            return -1;
        size_t chk = phys_end - phys;
        if (sz < chk)
            chk = sz;
        if (kernel_copyin(p_src, dmap + phys, chk))
            return -1;
        vaddr += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

static int userland_copyin(pid_t pid, const void *buf, intptr_t addr, size_t len) {
    // mdbg_copyin doesnt work above 8.20, so copy using kernel dmap
    // make sure the addr is faulted in using mdbg_copyout, which still works on higher fws
    void *tmp = malloc(len);
    if (tmp == NULL) {
        return -1;
    }

    int res = mdbg_copyout(pid, addr, tmp, len);
    free(tmp);
    if (res) {
        return -1;
    }

    unsigned long dmap;
    unsigned long cr3 = kernel_get_proc_cr3(pid, &dmap);
    if (cr3 == 0) {
        return -1;
    }

    return phys_copyin(addr, buf, len, dmap, cr3);
}

static int patch_shellui(int pid) {
    // make Sce.Vsh.Np.TrophyAccessor.Utils::IsOnlineModeAvailable always return false,
    // so that activated accounts, while connected to a network, can open the trophies menu

    // this one is redundant, starting 5.00? the out isAvailable of this is ignored and only trophy2 matters
    uint32_t libSceNpTrophy_handle = -1;
    // if shellui was just launched, the lib may not be loaded yet, try every 0.5s for up to 30s
    for (int i = 0; i < 60; i++) {
        if (kernel_dynlib_handle(pid, "libSceNpTrophy.sprx", &libSceNpTrophy_handle) == 0) {
            break;
        }
        usleep(500000);
    }
    if (libSceNpTrophy_handle == -1) {
        LOG_PUTS("Failed to get libSceNpTrophy handle, patch_shellui failed");
        return -1;
    }

    uint64_t sceNpTrophySystemIsServerAvailable_offset = kernel_dynlib_resolve(pid, libSceNpTrophy_handle, "-qjm2fFE64M");
    if (sceNpTrophySystemIsServerAvailable_offset == 0) {
        LOG_PUTS("kernel_dynlib_resolve(sceNpTrophySystemIsServerAvailable) failed, patch_shellui failed");
        return -1;
    }

    uint32_t libSceNpTrophy2_handle = -1;
    for (int i = 0; i < 60; i++) {
        if (kernel_dynlib_handle(pid, "libSceNpTrophy2.sprx", &libSceNpTrophy2_handle) == 0) {
            break;
        }
        usleep(500000);
    }
    if (libSceNpTrophy2_handle == -1) {
        LOG_PUTS("Failed to get libSceNpTrophy2 handle, patch_shellui failed");
        return -1;
    }

    uint64_t sceNpTrophy2SystemIsServerAvailable_offset = kernel_dynlib_resolve(pid, libSceNpTrophy2_handle, "7xSkVM0yhV0");
    if (sceNpTrophy2SystemIsServerAvailable_offset == 0) {
        LOG_PUTS("kernel_dynlib_resolve(sceNpTrophy2SystemIsServerAvailable) failed, patch_shellui failed");
        return -1;
    }

    // clang-format off
    const uint8_t fake_sceNpTrophySystemIsServerAvailable[] = {
        // mov byte ptr [rdi], 0
        0xC6, 0x07, 0x00, 
        // xor eax, eax
        0x31, 0xC0, 
        // ret
        0xC3
    };
    // clang-format on

    if (userland_copyin(pid, fake_sceNpTrophySystemIsServerAvailable, sceNpTrophySystemIsServerAvailable_offset, sizeof(fake_sceNpTrophySystemIsServerAvailable))) {
        LOG_PUTS("Failed to patch sceNpTrophySystemIsServerAvailable, patch_shellui failed");
        return -1;
    }

    if (userland_copyin(pid, fake_sceNpTrophySystemIsServerAvailable, sceNpTrophy2SystemIsServerAvailable_offset, sizeof(fake_sceNpTrophySystemIsServerAvailable))) {
        LOG_PUTS("Failed to patch sceNpTrophy2SystemIsServerAvailable, patch_shellui failed");
        return -1;
    }

    LOG_PUTS("Successfully patched SceShellUI trophy IsServerAvailable");
    return 0;
}

// https://github.com/ps5-payload-dev/klogsrv/blob/c1b64bd3d3b069a09b1a173a82858cba97a5656f/main.c#L266
static pid_t find_pid(const char *name) {
    int mib[4] = {1, 14, 8, 0};
    pid_t mypid = getpid();
    pid_t pid = PID_NOT_FOUND;
    size_t buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0)) {
        LOG_PERROR("sysctl");
        return PID_LOOKUP_ERROR;
    }

    if (!(buf = malloc(buf_size))) {
        LOG_PERROR("malloc");
        return PID_LOOKUP_ERROR;
    }

    if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        LOG_PERROR("sysctl");
        free(buf);
        return PID_LOOKUP_ERROR;
    }

    const size_t name_len = strlen(name);
    for (size_t offset = 0; offset < buf_size;) {
        int entry_size;
        if (buf_size - offset < sizeof(entry_size)) {
            pid = PID_LOOKUP_ERROR;
            break;
        }
        memcpy(&entry_size, buf + offset, sizeof(entry_size));
        if (entry_size < 447 + TDNAMLEN + 1 ||
            (size_t)entry_size > buf_size - offset) {
            pid = PID_LOOKUP_ERROR;
            break;
        }

        uint8_t *entry = buf + offset;
        pid_t entry_pid;
        memcpy(&entry_pid, entry + 72, sizeof(entry_pid));
        const char *entry_name = (const char *)entry + 447;
        if (name_len < TDNAMLEN + 1 &&
            strnlen(entry_name, TDNAMLEN + 1) == name_len &&
            memcmp(name, entry_name, name_len) == 0 &&
            entry_pid != mypid) {
            pid = entry_pid;
        }
        offset += (size_t)entry_size;
    }

    free(buf);

    return pid;
}

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
} app_info_t;

int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

static bool patch_new_shellui(pid_t pid, pid_t *patched_pid) {
    if (pid <= 0 || pid == *patched_pid) {
        return true;
    }

    LOG_PRINTF("Patching shellui instance (pid %d)...\n", pid);
    if (patch_shellui(pid) != 0) {
        return false;
    }

    *patched_pid = pid;
    return true;
}

static void *shellui_patch_thread(void *arg) {
    pid_t patched_pid = -1;
    pid_t syscore_pid = -1;
    int retry_checks = 0;
    bool retry_until_patched = false;
    int kq = -1;

    while (1) {
        if (kq < 0) {
            // shellui is restarted after rest mode, wait for new instances
            kq = kqueue();
            if (kq < 0) {
                LOG_PERROR("kqueue");
                sleep(1);
                continue;
            }
        }

        if (syscore_pid < 0) {
            syscore_pid = find_pid("SceSysCore.elf");
            if (syscore_pid < 0) {
                // SceSysCore may be temporarily absent during resume.
                pid_t shellui_pid = find_pid("SceShellUI");
                if (shellui_pid > 0) {
                    retry_until_patched = !patch_new_shellui(shellui_pid,
                                                               &patched_pid);
                    retry_checks = 0;
                }
                sleep(1);
                continue;
            }

            struct kevent kev;
            EV_SET(&kev, syscore_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
                   NOTE_FORK | NOTE_EXEC | NOTE_TRACK | NOTE_EXIT, 0, NULL);
            if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
                LOG_PERROR("kevent register SceSysCore");
                close(kq);
                kq = -1;
                syscore_pid = -1;
                sleep(1);
                continue;
            }

            // Cover a ShellUI instance that started before the event filter.
            pid_t shellui_pid = find_pid("SceShellUI");
            if (shellui_pid > 0) {
                retry_until_patched = !patch_new_shellui(shellui_pid,
                                                           &patched_pid);
                retry_checks = 0;
            } else if (shellui_pid == PID_LOOKUP_ERROR) {
                retry_until_patched = true;
                retry_checks = 0;
            }
        }

        struct kevent event;
        struct timespec timeout = {1, 0};
        int nev = kevent(kq, NULL, 0, &event, 1,
                         (retry_until_patched || retry_checks > 0) ? &timeout : NULL);
        if (nev < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_PERROR("kevent wait for SceShellUI");
            close(kq);
            kq = -1;
            syscore_pid = -1;
            sleep(1);
            continue;
        }

        if (nev == 0) {
            pid_t shellui_pid = find_pid("SceShellUI");
            if (shellui_pid == PID_LOOKUP_ERROR) {
                retry_until_patched = true;
                retry_checks = 0;
            } else if (shellui_pid > 0 && shellui_pid != patched_pid) {
                retry_until_patched = !patch_new_shellui(shellui_pid,
                                                           &patched_pid);
                retry_checks = 0;
            } else {
                if (shellui_pid > 0 && shellui_pid == patched_pid) {
                    retry_until_patched = false;
                }
                if (retry_checks > 0) {
                    --retry_checks;
                }
            }
            continue;
        }

        if (event.flags & EV_ERROR) {
            errno = (int)event.data;
            LOG_PERROR("SceSysCore process watch failed");
            close(kq);
            kq = -1;
            syscore_pid = -1;
            sleep(1);
            continue;
        }

        if (event.ident == (uintptr_t)syscore_pid &&
            (event.fflags & NOTE_EXIT)) {
            close(kq);
            kq = -1;
            syscore_pid = -1;
            patched_pid = -1;
            retry_checks = 0;
            retry_until_patched = false;
            continue;
        }

        if (event.fflags & NOTE_TRACKERR) {
            LOG_PUTS("Failed to track a SceSysCore child; re-registering");
            close(kq);
            kq = -1;
            syscore_pid = -1;
            continue;
        }

        if (!(event.fflags & NOTE_EXEC)) {
            continue;
        }

        pid_t new_pid = event.ident;
        app_info_t appinfo;
        if (sceKernelGetAppInfo(new_pid, &appinfo)) {
            LOG_PERROR("sceKernelGetAppInfo");
            retry_checks = SHELLUI_EVENT_RETRY_CHECKS;
            retry_until_patched = false;
            continue;
        }
        if (strncmp(appinfo.title_id, "NPXS40087",
                    sizeof(appinfo.title_id)) == 0) {
            retry_until_patched = !patch_new_shellui(new_pid, &patched_pid);
            retry_checks = 0;
        } else if (appinfo.title_id[0] == '\0') {
            // The title ID may not be ready at the instant NOTE_EXEC fires.
            retry_checks = SHELLUI_EVENT_RETRY_CHECKS;
            retry_until_patched = false;
        }
    }

    __builtin_unreachable();
}

int start_shellui_patch_thread() {
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, shellui_patch_thread, NULL);
    if (ret != 0) {
        errno = ret;
        LOG_PERROR("pthread_create");
        return -1;
    }

    pthread_detach(thread);
    return 0;
}
