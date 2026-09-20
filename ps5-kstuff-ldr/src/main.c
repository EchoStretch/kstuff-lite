/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */           

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <limits.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/event.h>

#include <machine/param.h>
#include <ps5/payload.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>

#include "image.h"
#include "ufs_mount.h"
#include "pfs_mount.h"
#include "pfsc_mount.h"
#include "exfat_mount.h"
#include "mount_helpers.h"
#include "shellui_patch.h"
#include "utils.h"
#include "../../lib/r0gdb-bootstrap.h"
#include "../../lib/shellcore-imports.h"

asm(".section .rodata\n"
    ".global ___ps5_kstuff_payload_bin\n"
    "___ps5_kstuff_payload_bin:\n"
    ".incbin \"../../ps5-kstuff/payload.bin\"\n");

extern char ___ps5_kstuff_payload_bin[];
int shellcore_import_got(int pid, uint64_t image_base, uint32_t required_mask,
                         uint64_t got[SHELLCORE_IMPORT_COUNT]);

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
                     (((x) & PF_W) ? PROT_WRITE : 0) | \
                     (((x) & PF_X) ? PROT_EXEC  : 0))

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

static int automount_disabled(void) {
    return access("/data/.kstuff_noautomount", F_OK) == 0;
}

static int mount_source(const char* src_path, char* out_mounted_path,
                        bool* out_temporary_mount)
{
    struct stat source_st;
    char image_path[MAX_PATH] = {0};
    bool is_ufs = false, is_pfs = false, is_pfsc = false, is_exfat = false;

    if (!src_path || !*src_path || !out_mounted_path ||
        !out_temporary_mount) {
        errno = EINVAL;
        return -1;
    }
    out_mounted_path[0] = '\0';
    *out_temporary_mount = false;

    /* A stale mount.lnk must not enter nmount or the image cleanup paths. */
    if (stat(src_path, &source_st) != 0) {
        return -1;
    }
    if (!S_ISDIR(source_st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    if (find_image_in_dir(src_path, image_path, sizeof(image_path), 
                          &is_ufs, &is_pfs, &is_pfsc, &is_exfat)) {
        
        klog_printf("Image detected in folder: %s\n", image_path);

        char mount_point[MAX_PATH] = {0};
        char nullfs_src[MAX_PATH] = {0};

        if (is_ufs && mount_ufs_image(image_path, mount_point)) {
            klog_printf("UFS image mounted\n");
            strncpy(nullfs_src, mount_point, sizeof(nullfs_src)-1);
            *out_temporary_mount = true;
        }
        else if (is_pfs && mount_pfs_image(image_path, mount_point)) {
            klog_printf("PFS image mounted\n");
            strncpy(nullfs_src, mount_point, sizeof(nullfs_src)-1);
            *out_temporary_mount = true;
        }
        else if (is_pfsc) {
            klog_printf("PFSC image detected: %s\n", strrchr(image_path, '/') ? 
                       strrchr(image_path, '/') + 1 : image_path);

            char pfsc_mount_point[MAX_PATH] = {0};
            if (mount_pfsc_image(image_path, pfsc_mount_point)) {
                strncpy(nullfs_src, pfsc_mount_point, sizeof(nullfs_src)-1);
                strncpy(mount_point, pfsc_mount_point, sizeof(mount_point)-1);
                *out_temporary_mount = true;

                // === NESTED IMAGE SUPPORT ===
                char nested_image[MAX_PATH] = {0};
                bool n_ufs = false, n_pfs = false, n_pfsc = false, n_exfat = false;

                klog_printf("Scanning for nested image inside PFSC...\n");
                if (find_image_in_dir(pfsc_mount_point, nested_image, sizeof(nested_image),
                                    &n_ufs, &n_pfs, &n_pfsc, &n_exfat)) {

                    char nested_mount[MAX_PATH] = {0};
                    bool nested_ok = false;

                    if (n_ufs) {
                        klog_printf("Nested UFS detected\n");
                        nested_ok = mount_ufs_image(nested_image, nested_mount);
                    } else if (n_pfs) {
                        klog_printf("Nested PFS detected\n");
                        nested_ok = mount_pfs_image(nested_image, nested_mount);
                    } else if (n_exfat) {
                        klog_printf("Nested exFAT detected\n");
                        nested_ok = mount_exfat_image(nested_image, nested_mount);
                    }

                    if (nested_ok && strlen(nested_mount) > 0) {
                        klog_printf("Successfully mounted nested image\n");
                        strncpy(nullfs_src, nested_mount, sizeof(nullfs_src)-1);
                        strncpy(mount_point, nested_mount, sizeof(mount_point)-1);
                    } else {
                        klog_printf("Nested mount failed - falling back to PFSC root\n");
                    }
                }
                // === END NESTED SUPPORT ===
            } else {
                klog_printf("PFSC mount failed\n");
            }
        }
        else if (is_exfat && mount_exfat_image(image_path, mount_point)) {
            klog_printf("exFAT image mounted\n");
            strncpy(nullfs_src, mount_point, sizeof(nullfs_src)-1);
            *out_temporary_mount = true;
        }

        if (strlen(nullfs_src) > 0) {
            strncpy(out_mounted_path, nullfs_src, PATH_MAX - 1);
            out_mounted_path[PATH_MAX - 1] = '\0';
            return 0;
        }

        klog_printf("Image mount failed, falling back to folder mode\n");
    }

    // No image or mount failed → use folder directly
    strncpy(out_mounted_path, src_path, PATH_MAX - 1);
    out_mounted_path[PATH_MAX - 1] = '\0';
    return 0;
}

static int bind_mount_title(const char* title_id, const char* src)
{
    char dst[PATH_MAX];
    char mounted_src[PATH_MAX] = {0};
    struct stat mounted_st;
    bool temporary_mount = false;
    bool created_dst = false;

    if (automount_disabled()) {
        return 0;
    }

    snprintf(dst, sizeof(dst), "/system_ex/app/%s", title_id);
    if (is_mounted(dst)) {
        /* Persistent directories are not proof that nullfs is still active. */
        return 0;
    }

    if (mount_source(src, mounted_src, &temporary_mount) != 0) {
        klog_perror("Skipping title with unavailable mount.lnk source");
        return -1;
    }
    if (stat(mounted_src, &mounted_st) != 0) {
        klog_perror("Prepared title source is not a directory");
        if (temporary_mount) {
            unmount(mounted_src, MNT_FORCE);
            rmdir(mounted_src);
        }
        return -1;
    }
    if (!S_ISDIR(mounted_st.st_mode)) {
        errno = ENOTDIR;
        klog_perror("Prepared title source is not a directory");
        if (temporary_mount) {
            unmount(mounted_src, MNT_FORCE);
            rmdir(mounted_src);
        }
        return -1;
    }

    if (unmount(dst, 0) != 0 && errno != EINVAL && errno != ENOENT) {
        klog_perror("Failed to unmount partially mounted title");
    }

    if (mkdir(dst, 0755) == 0) {
        created_dst = true;
    } else if (errno != EEXIST) {
        klog_perror("Failed to create mount directory for title");
        if (temporary_mount) {
            unmount(mounted_src, MNT_FORCE);
            rmdir(mounted_src);
        }
        return -1;
    }

    if (mount_nullfs(mounted_src, dst) != 0) {
        klog_perror("Failed to bind mount title with mount_nullfs");
        /* Never unmount the mount.lnk source itself. Only a temporary image
         * mount created above is owned by this invocation. */
        if (temporary_mount) {
            unmount(mounted_src, MNT_FORCE);
            rmdir(mounted_src);
        }
        if (created_dst) rmdir(dst);
        return -1;
    }

    klog_printf("Title Mounted Successfully: %s -> %s\n", mounted_src, dst);
    return 0;
}

static int read_mount_link(const char* path, char* buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    memset(buf, 0, size);
    ssize_t n = read(fd, buf, size - 1);
    if (n < 0) {
        klog_perror("Failed to read mount.lnk file");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int bind_mount_all_titles(const char* path) {
    char mountlnk[PATH_MAX];
    struct dirent *entry;
    struct stat st;
    DIR *dir = opendir(path);

    if (!dir) {
        klog_perror("Failed to open directory while binding mounts");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (automount_disabled()) {
            break;
        }
        if (strlen(entry->d_name) != 9) {
            continue;
        }

        snprintf(mountlnk, sizeof(mountlnk), "%s/%s/mount.lnk", path, entry->d_name);

        if (stat(mountlnk, &st) != 0) {
            continue;
        }

        if (read_mount_link(mountlnk, mountlnk, sizeof(mountlnk)) != 0) {
            continue;
        }

        // Run the mount step safely
        bind_mount_title(entry->d_name, mountlnk);
    }

    closedir(dir);
    return 0;
}

static int scan_and_mount_titles(void) {
    if (automount_disabled()) {
        return 0;
    }
    if (bind_mount_all_titles("/user/app") < 0) {
        klog_perror("Failed to bind mount /user/app titles");
        return -1;
    }

    return 0;
}

static const char *const watch_paths[] = {
    "/mnt",
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3",
    "/mnt/usb4", "/mnt/usb5", "/mnt/usb6", "/mnt/usb7"
};

#define WATCH_COUNT (sizeof(watch_paths) / sizeof(watch_paths[0]))

static bool mounted_usb_roots(unsigned int *mask) {
    struct stat parent;
    if (stat(watch_paths[0], &parent) != 0) {
        return false;
    }

    *mask = 0;
    for (size_t i = 1; i < WATCH_COUNT; i++) {
        struct stat root;
        if (stat(watch_paths[i], &root) == 0 &&
            root.st_dev != parent.st_dev) {
            *mask |= 1u << (i - 1);
        }
    }
    return true;
}

static void refresh_directory_watch(int kq, int *fd, const char *path) {
    struct stat current;
    if (stat(path, &current) != 0) {
        if (*fd >= 0) {
            close(*fd);
            *fd = -1;
        }
        return;
    }

    if (*fd >= 0) {
        struct stat watched;
        if (fstat(*fd, &watched) != 0 ||
            watched.st_dev != current.st_dev ||
            watched.st_ino != current.st_ino) {
            close(*fd);
            *fd = -1;
        }
    }
    if (*fd >= 0) {
        return;
    }

    int new_fd = open(path, O_RDONLY | O_DIRECTORY);
    if (new_fd < 0) {
        return;
    }
    struct kevent evt;
    EV_SET(&evt, new_fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE |
           NOTE_RENAME | NOTE_REVOKE, 0, NULL);
    if (kevent(kq, &evt, 1, NULL, 0, NULL) != 0) {
        close(new_fd);
        return;
    }
    *fd = new_fd;
}

static void close_directory_watches(int fds[WATCH_COUNT]) {
    for (size_t i = 0; i < WATCH_COUNT; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
            fds[i] = -1;
        }
    }
}

static void monitor_usb_changes(void) {
    struct kevent evt;
    int kq = -1;
    int watch_fds[WATCH_COUNT];
    for (size_t i = 0; i < WATCH_COUNT; i++) {
        watch_fds[i] = -1;
    }
    unsigned int mounted_mask = 0;
    bool mounted_mask_valid = false;
    bool automount_active = false;
    bool scan_pending = false;
    bool disabled_logged = false;

    while (1) {
        if (automount_disabled()) {
            if (!disabled_logged) {
                if (kq >= 0) {
                    close(kq);
                    kq = -1;
                }
                close_directory_watches(watch_fds);
                automount_active = false;
                mounted_mask_valid = false;
                scan_pending = false;
                klog_printf("Automount disabled by /data/.kstuff_noautomount\n");
                disabled_logged = true;
            }
            sleep(1);
            continue;
        }

        disabled_logged = false;
        if (!automount_active) {
            mounted_mask_valid = mounted_usb_roots(&mounted_mask);
            klog_printf("Remounting /system_ex and mounting titles with image support...\n");
            remount_system_ex();
            scan_and_mount_titles();
            automount_active = true;
        }

        unsigned int current_mask;
        if (mounted_usb_roots(&current_mask)) {
            if (mounted_mask_valid && current_mask != mounted_mask) {
                for (size_t i = 1; i < WATCH_COUNT; i++) {
                    unsigned int bit = 1u << (i - 1);
                    if ((current_mask & bit) != (mounted_mask & bit)) {
                        klog_printf("USB storage %s: %s\n", (current_mask & bit) ?
                                    "connected" : "disconnected", watch_paths[i]);
                    }
                }
            }
            if ((!mounted_mask_valid && current_mask) ||
                (mounted_mask_valid && (current_mask & ~mounted_mask))) {
                scan_pending = true;
            }
            mounted_mask = current_mask;
            mounted_mask_valid = true;
        }

        if (kq < 0) {
            kq = kqueue();
            if (kq < 0) {
                klog_perror("Failed to create kqueue");
            }
        }

        if (kq >= 0) {
            for (size_t i = 0; i < WATCH_COUNT; i++) {
                refresh_directory_watch(kq, &watch_fds[i], watch_paths[i]);
            }
        }

        if (scan_pending) {
            sleep(1); // let newly mounted storage settle
            if (!automount_disabled() && scan_and_mount_titles() < 0) {
                klog_perror("Failed to scan and bind mount titles after USB change");
            }
            scan_pending = false;
            continue;
        }

        if (kq < 0) {
            sleep(1);
            continue;
        }

        struct timespec timeout = {1, 0};
        int nev = kevent(kq, NULL, 0, &evt, 1, &timeout);
        if (nev < 0) {
            if (errno == EINTR) {
                continue;
            }
            klog_perror("kevent wait failed while monitoring USB changes");
            close(kq);
            kq = -1;
            close_directory_watches(watch_fds);
            continue;
        }
        if (nev > 0 && (evt.flags & EV_ERROR)) {
            errno = (int)evt.data;
            klog_perror("USB watch failed");
            close(kq);
            kq = -1;
            close_directory_watches(watch_fds);
            continue;
        }

        if (nev > 0 && evt.filter == EVFILT_VNODE) {
            for (size_t i = 1; i < WATCH_COUNT; i++) {
                if (evt.ident == (uintptr_t)watch_fds[i] &&
                    (mounted_mask & (1u << (i - 1))) &&
                    (evt.fflags & (NOTE_WRITE | NOTE_EXTEND))) {
                    scan_pending = true;
                    break;
                }
            }
        }
    }
}

static void
pt_load(const void* image, void* base, Elf64_Phdr *phdr) {
  if(phdr->p_memsz && phdr->p_filesz) {
      memcpy(base + phdr->p_vaddr, image + phdr->p_offset, phdr->p_filesz);
  }
}

int main(void) {
    sceKernelSetProcessName("kstuff.elf");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)___ps5_kstuff_payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(___ps5_kstuff_payload_bin + ehdr->e_phoff);
    void *base = (void*)0x0000000926100000;
    uintptr_t min_vaddr = -1;
    uintptr_t max_vaddr = 0;
    size_t base_size;

    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_vaddr < min_vaddr) {
            min_vaddr = phdr[i].p_vaddr;
        }
        if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    if((base=mmap(base, base_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    for(int i=0; i<ehdr->e_phnum; i++) {
        switch(phdr[i].p_type) {
        case PT_LOAD:
            pt_load(___ps5_kstuff_payload_bin, base, &phdr[i]);
            break;
        }
    }

    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
            continue;
        }
        if(mprotect(base + phdr[i].p_vaddr, ROUND_PG(phdr[i].p_memsz),
                    PFLAGS(phdr[i].p_flags))) {
            perror("mprotect");
            return EXIT_FAILURE;
        }
    }

    void (*entry)(payload_args_t*, uint64_t,
                  intptr_t (*)(int, uint32_t, const char*),
                  int (*)(int, const char*, uint32_t*),
                  kstuff_shellcore_imports_fn) =
        base + ehdr->e_entry;
    payload_args_t* args = payload_get_args();

    // allow dlsym on 5.00+ - https://gist.github.com/TheOfficialFloW/7174351201b5260d7780780f4059bebf#file-exploitnetcontrolimpl-java-L851
    uint64_t proc = kernel_get_proc(-1);
    uint64_t p_dynlib = kernel_getlong(proc + 0x3e8);
    uint64_t dynlib_eboot = kernel_getlong(p_dynlib + 0x00);
    uint64_t eboot_segments = kernel_getlong(dynlib_eboot + 0x40);
    kernel_setlong(eboot_segments + 0x08, 0); // addr
    kernel_setlong(eboot_segments + 0x10, 0xFFFFFFFFFFFFFFFFL); // size

    entry(args, KSTUFF_DYNLIB_RESOLVER_MAGIC,
          kernel_dynlib_resolve, kernel_dynlib_handle,
          shellcore_import_got);
    if(*args->payloadout == 0) {
        puts("patching app.db");
        *args->payloadout = patch_app_db();
    }
    start_shellui_patch_thread();

    monitor_usb_changes();

    return 0; 
}
