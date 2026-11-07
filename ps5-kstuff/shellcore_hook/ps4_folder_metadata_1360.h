#ifndef KSTUFF_PS4_FOLDER_METADATA_1360_H
#define KSTUFF_PS4_FOLDER_METADATA_1360_H

#include "ps4_folder_metadata.h"
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>

extern const unsigned char ps4_folder_metadata_blob_start[];
extern const unsigned char ps4_folder_metadata_blob_end[];

/* Retail 13.60: use the existing PKG metadata parsers for directory sources.
 * The parsers keep their ordinary format/ID validation and object ownership.
 * Only their entry reads are adapted; non-directory sources call the original.
 */
static int install_shellcore_folder_metadata_1360_stopped(int pid, uint64_t base, uint64_t text_end,
                                                          uint64_t dmap, uint64_t cr3,
                                                          struct shellcore_locked_pages *locked,
                                                          int *unsafe_to_resume)
{
    static const struct
    {
        uint32_t offset;
        unsigned char original[5];
        uint32_t target;
        unsigned char opcode;
    } sites[] = {
        {0xe79d60, {0x31, 0xc0, 0xc3, 0xcc, 0xcc}, 0xe7b810, 0xe9},
        {0xe79d70, {0x31, 0xc0, 0xc3, 0xcc, 0xcc}, 0xe7b990, 0xe9},
        {0xe7b875, {0xe8, 0x06, 0xf7, 0xff, 0xff}, 0x1963010, 0xe8},
        {0xe7ba08, {0xe8, 0x73, 0xf5, 0xff, 0xff}, 0x1963010, 0xe8},
    };
    static const unsigned char allocator[16] = {0x48, 0x89, 0xfe, 0x48, 0x8d, 0x3d, 0xbe, 0xae,
                                                0x30, 0x01, 0xe9, 0x31, 0x18, 0xa4, 0x00, 0xcc};
    static const unsigned char release[16] = {0x48, 0x89, 0xfe, 0x48, 0x8d, 0x3d, 0x8e, 0xae,
                                              0x30, 0x01, 0xe9, 0x21, 0x18, 0xa4, 0x00, 0xcc};
    const size_t count = sizeof(sites) / sizeof(sites[0]);
    const size_t blob_size = ps4_folder_metadata_blob_end - ps4_folder_metadata_blob_start;
    const uint64_t cave = base + 0x1963000;
    unsigned char trampoline[64] = {0}, snapshot[64], patch[4][5];
    if(!blob_size || blob_size > 0x4000 || cave + sizeof(trampoline) > text_end)
        return shellcore_ppr_fail("PS4 folder metadata: invalid code range");
    if(lock_shellcore_range(pid, cave, sizeof(trampoline), locked) ||
       phys_copyout(snapshot, cave, sizeof(snapshot), dmap, cr3) ||
       !shellcore_bytes_equal(snapshot, trampoline, sizeof(snapshot)))
        return shellcore_ppr_fail("PS4 folder metadata: trampoline cave in use");
    const uint32_t functions[] = {0xf1d740, 0xf1d770};
    for(size_t i = 0; i < 2; i++)
        if(base + functions[i] + 16 > text_end ||
           lock_shellcore_range(pid, base + functions[i], 16, locked) ||
           phys_copyout(snapshot, base + functions[i], 16, dmap, cr3) ||
           !shellcore_bytes_equal(snapshot, i == 0 ? allocator : release, 16))
            return shellcore_ppr_fail("PS4 folder metadata: allocator mismatch");
    for(size_t i = 0; i < count; i++)
    {
        uint64_t address = base + sites[i].offset;
        int64_t distance = (int64_t)(base + sites[i].target) - (int64_t)(address + 5);
        int32_t relative = (int32_t)distance;
        if(address + 5 > text_end || (int64_t)relative != distance ||
           lock_shellcore_range(pid, address, 5, locked) ||
           phys_copyout(snapshot, address, 5, dmap, cr3) ||
           !shellcore_bytes_equal(snapshot, sites[i].original, 5))
            return shellcore_ppr_fail("PS4 folder metadata: original instruction mismatch");
        patch[i][0] = sites[i].opcode;
        memcpy(patch[i] + 1, &relative, sizeof(relative));
    }

    uint64_t got[SHELLCORE_IMPORT_COUNT], helpers[3];
    uint32_t mask = SHELLCORE_IMPORT_BIT(SHELLCORE_IMPORT_CLOSE) |
                    SHELLCORE_IMPORT_BIT(SHELLCORE_IMPORT_OPEN) |
                    SHELLCORE_IMPORT_BIT(SHELLCORE_IMPORT_PREAD);
    if(kstuff_shellcore_imports(pid, base, mask, got))
        return shellcore_ppr_fail("PS4 folder metadata: imports unavailable");
    for(size_t i = 0; i < 3; i++)
    {
        uint64_t lazy_plt;
        if(read_shellcore_import(pid, base, text_end, got[i], dmap, cr3, locked, &helpers[i],
                                 &lazy_plt))
            return shellcore_ppr_fail("PS4 folder metadata: file import mismatch");
        if(lazy_plt)
            helpers[i] = lazy_plt;
    }
    uint64_t error_location = 0;
    static const uint32_t handles[] = {1, 0x2001};
    for(size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); i++)
    {
        uint64_t candidate = kstuff_dynlib_resolve(pid, handles[i], "9BcDykPmo1I");
        if(candidate >= 0x10000 && candidate < 0x0000800000000000ull)
        {
            error_location = candidate; /* __error */
            break;
        }
    }
    if(!error_location)
        return shellcore_ppr_fail("PS4 folder metadata: errno export unavailable");

    struct ps4_folder_metadata_env environment = {0};
    uint64_t addresses[] = {base + 0xe7af80, helpers[1],      helpers[2],    helpers[0],
                            base + 0xf1d740, base + 0xf1d770, error_location};
    _Static_assert(offsetof(struct ps4_folder_metadata_env, filenames) == 7 * 8,
                   "folder metadata function pointer ABI mismatch");
    _Static_assert(sizeof(environment) <= 0x4000, "folder metadata environment too large");
    memcpy(&environment, addresses, sizeof(addresses));
    memcpy(environment.filenames[0], "/nptitle.dat", 13);
    memcpy(environment.filenames[1], "/npbind.dat", 12);
    uint64_t mapping = remote_syscall(pid, SYS_mmap, 0, 0x8000, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0);
    if(mapping < 0x10000 || mapping >= 0x0000800000000000ull - 0x8000)
        return shellcore_ppr_fail("PS4 folder metadata: mmap failed");
    size_t touched = 0;
    uint64_t code = mapping + 0x4000;
    if(remote_syscall(pid, SYS_mlock, mapping, 0x8000, 0, 0, 0, 0) ||
       phys_copyin(mapping, &environment, sizeof(environment), dmap, cr3) ||
       verify_shellcore_blob(mapping, (const unsigned char *)&environment, sizeof(environment),
                             dmap, cr3) ||
       phys_copyin(code, ps4_folder_metadata_blob_start, blob_size, dmap, cr3) ||
       verify_shellcore_blob(code, ps4_folder_metadata_blob_start, blob_size, dmap, cr3) ||
       remote_syscall(pid, SYS_mprotect, code, 0x4000, PROT_READ | PROT_EXEC, 0, 0, 0))
        goto failed;
    /* XOM trampoline reads all addresses as instruction immediates. */
    memcpy(trampoline, "PS4META1360", 12);
    trampoline[16] = 0x49;
    trampoline[17] = 0xb9; /* movabs env, r9 */
    memcpy(trampoline + 18, &mapping, 8);
    trampoline[26] = 0x49;
    trampoline[27] = 0xbb; /* movabs code, r11 */
    memcpy(trampoline + 28, &code, 8);
    trampoline[36] = 0x41;
    trampoline[37] = 0xff;
    trampoline[38] = 0xe3;
    if(phys_copyin(cave, trampoline, sizeof(trampoline), dmap, cr3) ||
       verify_shellcore_blob(cave, trampoline, sizeof(trampoline), dmap, cr3))
        goto failed;
    for(size_t i = 0; i < count; i++)
    {
        uint64_t address = base + sites[i].offset;
        if(phys_copyout(snapshot, address, 5, dmap, cr3) ||
           !shellcore_bytes_equal(snapshot, sites[i].original, 5))
            goto failed;
        touched = i + 1;
        if(phys_copyin(address, patch[i], 5, dmap, cr3) ||
           verify_shellcore_blob(address, patch[i], 5, dmap, cr3))
            goto failed;
    }
    return 0;

failed:;
    int rollback_failed = 0;
    for(size_t i = 0; i < touched; i++)
        if(phys_copyin(base + sites[i].offset, sites[i].original, 5, dmap, cr3) ||
           verify_shellcore_blob(base + sites[i].offset, sites[i].original, 5, dmap, cr3))
            rollback_failed = 1;
    if(!touched)
    {
        /* No published branch can reach either allocation yet. */
        unsigned char zero[64] = {0};
        if(phys_copyin(cave, zero, sizeof(zero), dmap, cr3) ||
           verify_shellcore_blob(cave, zero, sizeof(zero), dmap, cr3))
            rollback_failed = 1;
        remote_syscall(pid, SYS_munmap, mapping, 0x8000, 0, 0, 0, 0);
    }
    /* Retain code/env after publication: an in-flight reader can still use it. */
    if(rollback_failed)
        *unsafe_to_resume = 1;
    return shellcore_ppr_fail(rollback_failed ? "PS4 folder metadata: rollback failed"
                                              : "PS4 folder metadata: install failed");
}

/* These ucred offsets match the SDK's retail 13.60 layout. Change only this
 * process's auth/caps for each ptrace operation and verify their restoration.
 */
static int folder_metadata_ptrace(int request, int pid, int *restored)
{
    *restored = 1;
    uint64_t self = kernel_get_proc(getpid());
    uint64_t ucred = self ? kread8(self + 0x40) : 0;
    if((ucred >> 48) != 0xffff)
        return -1;
    uint64_t saved[3], check[3];
    if(copyout(saved, ucred + 0x58, sizeof(saved)) != sizeof(saved))
        return -1;
    uint64_t privileged[3] = {0x4800000000010003ull, UINT64_MAX, UINT64_MAX};
    int result = -1;
    *restored = 0;
    if(copyin(ucred + 0x58, privileged, sizeof(privileged)) == sizeof(privileged) &&
       copyout(check, ucred + 0x58, sizeof(check)) == sizeof(check) &&
       shellcore_bytes_equal((unsigned char *)check, (unsigned char *)privileged, sizeof(check)))
        result = ptrace(request, pid, 0, 0);
    int saved_errno = errno;
    for(int attempt = 0; attempt < 3 && !*restored; attempt++)
        if(copyin(ucred + 0x58, saved, sizeof(saved)) == sizeof(saved) &&
           copyout(check, ucred + 0x58, sizeof(check)) == sizeof(check) &&
           shellcore_bytes_equal((unsigned char *)check, (unsigned char *)saved, sizeof(check)))
            *restored = 1;
    errno = saved_errno;
    return result;
}

static void folder_metadata_park(const char *reason)
{
    notify(reason);
    /* Never exit the tracer or resume a target with unverified instructions. */
    for(;;)
    {
        struct timespec delay = {1, 0};
        nanosleep(&delay, 0);
    }
}

static int install_shellcore_folder_metadata_1360(int pid, uint64_t base, uint64_t text_end,
                                                  uint64_t dmap, uint64_t cr3,
                                                  struct shellcore_locked_pages *locked)
{
    if((r0gdb_get_fw_version() >> 16) != 0x1360 || get_kit_type() != KIT_RETAIL)
        return 0;
    int restored;
    int attached = folder_metadata_ptrace(PT_ATTACH, pid, &restored);
    if(!restored)
        folder_metadata_park("PS4 folder metadata: credential restore failed");
    if(attached)
        return shellcore_ppr_fail("PS4 folder metadata: attach failed");
    int status = 0;
    pid_t stopped;
    do
    {
        stopped = wait4(pid, &status, 0, 0);
    } while(stopped < 0 && errno == EINTR);
    int result = -1, unsafe = 0;
    if(stopped == pid && WIFSTOPPED(status))
        result = install_shellcore_folder_metadata_1360_stopped(pid, base, text_end, dmap, cr3,
                                                                locked, &unsafe);
    else
        shellcore_ppr_fail("PS4 folder metadata: target stop unconfirmed");
    if(unsafe)
        folder_metadata_park("PS4 folder metadata: rollback failed; target kept stopped");
    int detached = folder_metadata_ptrace(PT_DETACH, pid, &restored);
    if(detached || !restored)
        folder_metadata_park("PS4 folder metadata: detach/credential restore failed");
    return result;
}

#endif
