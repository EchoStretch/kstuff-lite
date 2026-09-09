#ifndef KSTUFF_H
#define KSTUFF_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>

#if !defined(__x86_64__)
#error "kstuff client requests require x86-64"
#endif

#ifdef __cplusplus
extern "C" int getpid(void);
#else
int getpid(void);
#endif

#define KSTUFF_PROBE_OP UINT32_C(0xffffffff)
#define KSTUFF_SELF_ELEVATION_OP UINT32_C(7)
#define KSTUFF_SELF_INSPECTION_OP UINT32_C(8)
#define KSTUFF_SELF_ELEVATION_MAGIC UINT64_C(0x31564c4553355350)
#define KSTUFF_SELF_ELEVATION_ABI_VERSION UINT64_C(1)
#define KSTUFF_SELF_INSPECTION_AUTH_ID UINT64_C(1)

typedef enum kstuff_profile {
    KSTUFF_PROFILE_DATA_ACCESS = 1,
    KSTUFF_PROFILE_PROCESS_MEMORY = 2,
    KSTUFF_PROFILE_DEBUG = 3,
} kstuff_profile_t;

/*
 * Client functions return zero on success or a positive errno value on
 * failure. They do not set errno. A successful profile request changes only
 * the calling process and remains active for that process's lifetime.
 */
static inline int kstuff_internal_request(uint32_t operation, uint64_t argument0,
                                          uint64_t argument1, uint64_t argument2,
                                          uint64_t* result)
{
    const uintptr_t syscall_entry = (uintptr_t)(void*)&getpid + 7;
    uint64_t value = ((uint64_t)operation << 32) | UINT64_C(39);
    register uint64_t argument3 __asm__("r10") = 0;
    register uint64_t argument4 __asm__("r8") = 0;
    register uint64_t argument5 __asm__("r9") = 0;
    uint8_t failed = 0;

    if(!result)
        return EINVAL;

    __asm__ volatile("call *%[entry]\n\tsetc %[failed]"
                     : "+a"(value), [failed] "=qm"(failed), "+r"(argument3),
                       "+r"(argument4), "+r"(argument5)
                     : [entry] "r"(syscall_entry), "D"(argument0), "S"(argument1),
                       "d"(argument2)
                     : "rcx", "r11", "memory");

    if(failed)
        return value && value <= INT_MAX ? (int)value : EIO;
    *result = value;
    return 0;
}

/* Verify that the compatible kstuff request bridge is active. */
static inline int kstuff_probe(void)
{
    uint64_t result;
    int error = kstuff_internal_request(KSTUFF_PROBE_OP, 0, 0, 0, &result);
    return error ? error : result ? EPROTO : 0;
}

/* Explicitly apply one fixed capability profile to the calling process. */
static inline int kstuff_request_profile(kstuff_profile_t profile)
{
    uint64_t result;
    int error;

    if(profile != KSTUFF_PROFILE_DATA_ACCESS
    && profile != KSTUFF_PROFILE_PROCESS_MEMORY
    && profile != KSTUFF_PROFILE_DEBUG)
        return EINVAL;

    error = kstuff_internal_request(KSTUFF_SELF_ELEVATION_OP,
                                    KSTUFF_SELF_ELEVATION_MAGIC,
                                    KSTUFF_SELF_ELEVATION_ABI_VERSION,
                                    (uint64_t)profile, &result);
    return error ? error : result ? EPROTO : 0;
}

/* Read only the calling process's current kernel credential authority ID. */
static inline int kstuff_get_authority_id(uint64_t* authority_id)
{
    int error;

    if(!authority_id)
        return EINVAL;
    if((error = kstuff_probe()))
        return error;
    return kstuff_internal_request(KSTUFF_SELF_INSPECTION_OP,
                                   KSTUFF_SELF_ELEVATION_MAGIC,
                                   KSTUFF_SELF_ELEVATION_ABI_VERSION,
                                   KSTUFF_SELF_INSPECTION_AUTH_ID, authority_id);
}

#endif
