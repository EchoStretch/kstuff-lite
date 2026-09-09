#include <string.h>
#include <errno.h>
#include "fpkg.h"
#include "utils.h"
#include "traps.h"
#include "log.h"
#include "pfs_crypto.h"
#include "fakekeys.h"
#include "fpu.h"

extern char sceSblServiceMailbox[];
extern char sceSblServiceMailbox_lr_verifySuperBlock[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_1[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_2[];
extern char sceSblServiceRequest_lr_registerMountKey_1[];
extern char sceSblServiceRequest_lr_registerMountKey_2[];
extern char sceSblServiceCryptAsync_deref_singleton[];
extern char crypt_message_resolve[];
extern char doreti_iret[];

/* 9.40-only deltas from the already-relocated sceSblServiceMailbox symbol. */
enum {
    /* sceSblServiceMailbox is 0xffffffff956c8730 in the 9.40 IDA image. */
    /* Exact key-index wrappers used only while setup_a53io_pkg_keys runs. */
    PPR_PFS_940_GET_XTS_INDEX_FROM_MAILBOX = 0x5b2b80,
    PPR_PFS_940_GET_CMAC_INDEX_FROM_MAILBOX = 0x5b2ce0,
    PPR_PFS_940_GET_XTS_RETURN_BEFORE_MAILBOX = 0x208902,
    PPR_PFS_940_GET_CMAC_RETURN_BEFORE_MAILBOX = 0x2088b4,
    /* cleanup_a53io_pkg_keys entry 0xffffffff954b7d60. */
    PPR_PFS_940_CLEANUP_KEYS_BEFORE_MAILBOX = 0x2109d0,
    /*
     * sceSblPfsClearKey's tree-miss status instruction at
     * 0xffffffff953e0409.  The private FD/FC pair is deliberately absent
     * from that tree, so complete only that exact miss as success.
     */
    PPR_PFS_940_CLEAR_KEY_MISSING_BEFORE_MAILBOX = 0x2e8327,
    /*
     * The PPR verifyImage mailbox return at 0xffffffff953defa0 is
     * 0x1d00 bytes before the existing verifySuperBlock return at
     * 0xffffffff953e0ca0.  Express it relative to the already verified
     * firmware symbol so no new mandatory offset is added for other FW.
     */
    PPR_PFS_940_VERIFY_IMAGE_BEFORE_VERIFY_SUPERBLOCK = 0x1d00,
    /* verifyImage LR 0xffffffff953defa0 -> no-key success 0xffffffff953df2dc. */
    PPR_PFS_940_VERIFY_IMAGE_NO_KEY_SUCCESS_FROM_LR = 0x33c,
};

enum {
    PPR_PFS_CONTROL_PLAINTEXT_NOAUTH = 0x0009,
    PPR_PFS_MODE_NATIVE_ENCRYPTED = 0x000d,
    PPR_PFS_SESSION_ARMED = 1,
    PPR_PFS_SESSION_ACTIVE = 2,
    PPR_PFS_SESSION_STATE_MASK = 3,
    PPR_PFS_SESSION_PAIR_OWNED = 4,
    PPR_PFS_SESSION_PAIR_INFLIGHT = 8,
    PPR_PLAINTEXT_PROTOCOL_VERSION = 8,
    PPR_FIH_SIZE = 0x1000,
    PPR_SUPERBLOCK_SIZE = 0x5a0,
    PPR_STAGING_SIZE = PPR_FIH_SIZE + PPR_SUPERBLOCK_SIZE,
    PPR_CONTROL_BEGIN = 1,
    PPR_CONTROL_WRITE = 2,
    PPR_CONTROL_CHECK = 3,
};

/*
 * Private verifyImage handles.  They deliberately are not -1: on 9.40
 * ppfs_read_outer_block treats ekey == -1 as a request for the unsupported
 * ppfs_read_nsid2_plain_icv path even when the on-disk mode is 0x0d.
 * These handles are never registered in the secure-module key trees.
 */
#define PPR_PFS_PLAINTEXT_XTS_HANDLE  (UINT32_MAX - 2u)
#define PPR_PFS_PLAINTEXT_CMAC_HANDLE (UINT32_MAX - 3u)

static const uint8_t ppr_plaintext_seed_marker[16] =
    "PPRPLAIN-NOAUTH!";

static uint64_t ppr_pfs_plaintext_get_xts_index(void)
{
    if(FWVER != 0x940)
        return 0;
    return (uint64_t)sceSblServiceMailbox
         + PPR_PFS_940_GET_XTS_INDEX_FROM_MAILBOX;
}

static uint64_t ppr_pfs_plaintext_get_cmac_index(void)
{
    if(FWVER != 0x940)
        return 0;
    return (uint64_t)sceSblServiceMailbox
         + PPR_PFS_940_GET_CMAC_INDEX_FROM_MAILBOX;
}

static uint64_t ppr_pfs_plaintext_cleanup_keys(void)
{
    if(FWVER != 0x940)
        return 0;
    return (uint64_t)sceSblServiceMailbox
         - PPR_PFS_940_CLEANUP_KEYS_BEFORE_MAILBOX;
}

static uint64_t ppr_pfs_plaintext_clear_key_missing(void)
{
    if(FWVER != 0x940)
        return 0;
    return (uint64_t)sceSblServiceMailbox
         - PPR_PFS_940_CLEAR_KEY_MISSING_BEFORE_MAILBOX;
}

static void retain_ppr_plaintext_key_pair(void)
{
    __atomic_fetch_add(&shared_area.ppr_plaintext_key_pairs_outstanding,
                       1, __ATOMIC_RELEASE);
}

static int has_ppr_plaintext_key_pair(void)
{
    return __atomic_load_n(
        &shared_area.ppr_plaintext_key_pairs_outstanding,
        __ATOMIC_ACQUIRE) != 0;
}

static int release_ppr_plaintext_key_pair(uint64_t* xts_remaining,
                                           uint64_t* cmac_remaining)
{
    uint64_t* counter = &shared_area.ppr_plaintext_key_pairs_outstanding;
    uint64_t old = __atomic_load_n(counter, __ATOMIC_ACQUIRE);
    while(old)
    {
        if(__atomic_compare_exchange_n(counter, &old, old - 1, 0,
                                       __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE))
        {
            if(xts_remaining)
                *xts_remaining = old - 1;
            if(cmac_remaining)
                *cmac_remaining = old - 1;
            return 1;
        }
    }
    return 0;
}

static uint64_t ppr_pfs_verify_image_lr(void)
{
    if(FWVER != 0x940)
        return 0;
    return (uint64_t)sceSblServiceMailbox_lr_verifySuperBlock
         - PPR_PFS_940_VERIFY_IMAGE_BEFORE_VERIFY_SUPERBLOCK;
}

static uint64_t canonicalize_debug_kernel_pointer(uint64_t value)
{
    if((value >> 48) == 0xdeb7)
        value |= 0xffffull << 48;
    return value;
}

static void canonicalize_debug_gprs(uint64_t* regs)
{
    static const uint8_t gprs[] = {
        RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8,
        R9, R10, R11, R12, R13, R14, R15,
    };
    for(size_t i = 0; i < sizeof(gprs); i++)
        regs[gprs[i]] = canonicalize_debug_kernel_pointer(regs[gprs[i]]);
}

static int zero_kernel_checked(uint64_t dst, uint64_t size)
{
    static const uint8_t zero[256] = {0};

    if(dst + size < dst)
        return EFAULT;
    while(size)
    {
        size_t current = size < sizeof(zero) ? (size_t)size : sizeof(zero);
        if(copy_to_kernel(dst, zero, current))
            return EFAULT;
        dst += current;
        size -= current;
    }
    return 0;
}

static uint16_t load_u16_unaligned(const uint8_t* p)
{
    uint16_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static uint64_t load_u64_unaligned(const uint8_t* p)
{
    uint64_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static uint64_t validate_ppr_plaintext_staging(
    const struct kstuff_ppr_plaintext_staging* staging)
{
    const uint8_t* fih = staging->fih;
    const uint8_t* sblock = staging->superblock;
    uint64_t failed = 0;
    if(memcmp(fih, "\x7f" "FIH", 4)) failed |= 1ull << 0;
    if(load_u64_unaligned(fih + 0x10) != 0x10000) failed |= 1ull << 1;
    if(load_u64_unaligned(fih + 0x28) != 0x10000) failed |= 1ull << 2;
    if(load_u64_unaligned(fih + 0x60) != 0x10000) failed |= 1ull << 3;
    if(load_u64_unaligned(sblock) != 2) failed |= 1ull << 4;
    if(load_u64_unaligned(sblock + 8) <= 0x01332a0a) failed |= 1ull << 5;
    if(load_u16_unaligned(sblock + 0x1c)
                                      != PPR_PFS_MODE_NATIVE_ENCRYPTED)
        failed |= 1ull << 6;
    if(load_u64_unaligned(sblock + 0x20) != 0x10000) failed |= 1ull << 7;
    if(memcmp(sblock + 0x370, ppr_plaintext_seed_marker,
              sizeof(ppr_plaintext_seed_marker)))
        failed |= 1ull << 9;
    return failed;
}

static int get_current_ppr_thread(uint64_t* td)
{
    if(copy_current_thread_from_pcpu_cached(td))
        return EFAULT;
    *td = canonicalize_debug_kernel_pointer(*td);
    return (*td >> 48) == 0xffff ? 0 : EFAULT;
}

static void release_ppr_plaintext_staging(uint64_t td)
{
    struct kstuff_ppr_plaintext_staging* staging =
        &shared_area.ppr_plaintext_staging;
    if(__atomic_load_n(&staging->td, __ATOMIC_ACQUIRE) != td)
        return;
    __atomic_store_n(&staging->ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&staging->bytes_written, 0, __ATOMIC_RELAXED);
    memset(staging->fih, 0, sizeof(staging->fih));
    memset(staging->superblock, 0, sizeof(staging->superblock));
    __atomic_store_n(&staging->td, 0, __ATOMIC_RELEASE);
}

static int begin_current_ppr_plaintext_staging(uint64_t td)
{
    struct kstuff_ppr_plaintext_staging* staging =
        &shared_area.ppr_plaintext_staging;
    uint64_t owner = __atomic_load_n(&staging->td, __ATOMIC_ACQUIRE);
    if(owner && owner != td)
        return EBUSY;
    if(!owner)
    {
        uint64_t expected = 0;
        if(!__atomic_compare_exchange_n(&staging->td, &expected, td, 0,
                                        __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
            return EBUSY;
    }
    if(__atomic_load_n(&staging->ready, __ATOMIC_ACQUIRE))
        return EBUSY;
    memset(staging->fih, 0, sizeof(staging->fih));
    memset(staging->superblock, 0, sizeof(staging->superblock));
    __atomic_store_n(&staging->bytes_written, 0, __ATOMIC_RELEASE);
    return 0;
}

static int write_current_ppr_plaintext_staging(uint64_t td,
                                               uint64_t offset,
                                               uint64_t unused,
                                               uint64_t word1,
                                               uint64_t word2)
{
    (void)unused;
    struct kstuff_ppr_plaintext_staging* staging =
        &shared_area.ppr_plaintext_staging;
    if(__atomic_load_n(&staging->td, __ATOMIC_ACQUIRE) != td
    || __atomic_load_n(&staging->ready, __ATOMIC_ACQUIRE))
        return EPERM;
    uint64_t written = __atomic_load_n(&staging->bytes_written,
                                       __ATOMIC_ACQUIRE);
    if(offset != written || offset >= PPR_STAGING_SIZE)
        return EINVAL;

    uint8_t chunk[16];
    memcpy(chunk, &word1, 8);
    memcpy(chunk + 8, &word2, 8);
    size_t size = PPR_STAGING_SIZE - offset;
    if(size > sizeof(chunk))
        size = sizeof(chunk);
    if(offset < PPR_FIH_SIZE)
    {
        size_t fih_size = PPR_FIH_SIZE - offset;
        if(fih_size > size)
            fih_size = size;
        memcpy(staging->fih + offset, chunk, fih_size);
        if(fih_size < size)
            memcpy(staging->superblock, chunk + fih_size, size - fih_size);
    }
    else
    {
        memcpy(staging->superblock + offset - PPR_FIH_SIZE, chunk, size);
    }
    __atomic_store_n(&staging->bytes_written, offset + size,
                     __ATOMIC_RELEASE);
    return 0;
}

static int arm_current_ppr_plaintext_latch(uint64_t* armed_td)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return 0;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        uint64_t owner = __atomic_load_n(&latch->td,
                                         __ATOMIC_ACQUIRE);
        if(owner == td)
        {
            uint64_t expected = 0;
            if(!__atomic_compare_exchange_n(
                   &latch->state, &expected, PPR_PFS_SESSION_ARMED, 0,
                   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return 0;
            if(armed_td)
                *armed_td = td;
            return 1;
        }
        if(!owner)
        {
            uint64_t expected = 0;
            if(__atomic_compare_exchange_n(&latch->td,
                                           &expected, td, 0,
                                           __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE))
            {
                __atomic_store_n(&latch->state, PPR_PFS_SESSION_ARMED,
                                 __ATOMIC_RELEASE);
                if(armed_td)
                    *armed_td = td;
                return 1;
            }
        }
    }
    return 0;
}

static int consume_current_ppr_plaintext_latch(uint64_t* consumed_td)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return 0;
    if(consumed_td)
        *consumed_td = td;
    if(__atomic_load_n(&shared_area.ppr_plaintext_staging.td,
                       __ATOMIC_ACQUIRE) != td
    || !__atomic_load_n(&shared_area.ppr_plaintext_staging.ready,
                        __ATOMIC_ACQUIRE))
        return 0;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td,
                           __ATOMIC_ACQUIRE) != td)
            continue;
        uint64_t expected = PPR_PFS_SESSION_ARMED;
        int activated = __atomic_compare_exchange_n(
            &latch->state, &expected, PPR_PFS_SESSION_ACTIVE, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        /*
         * Every CPU has a separate uelf image, so this state must live in
         * shared_area rather than in this image's .bss. Same-thread ownership,
         * the one-shot armed bit, exact LR, and the verified request shape are
         * the authorization boundary.
         */
        return activated;
    }
    return 0;
}

static int retain_current_ppr_plaintext_key_pair(uint64_t td)
{
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td, __ATOMIC_ACQUIRE) != td)
            continue;

        uint64_t old = __atomic_load_n(&latch->state, __ATOMIC_ACQUIRE);
        for(;;)
        {
            if((old & PPR_PFS_SESSION_STATE_MASK) != PPR_PFS_SESSION_ACTIVE
            || (old & PPR_PFS_SESSION_PAIR_OWNED))
                return 0;
            uint64_t next = old | PPR_PFS_SESSION_PAIR_OWNED
                                | PPR_PFS_SESSION_PAIR_INFLIGHT;
            if(__atomic_compare_exchange_n(&latch->state, &old, next, 0,
                                           __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE))
            {
                retain_ppr_plaintext_key_pair();
                return 1;
            }
        }
    }
    return 0;
}

static int finish_current_ppr_plaintext_key_pair(uint64_t td,
                                                  int syscall_failed,
                                                  uint64_t* remaining)
{
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td, __ATOMIC_ACQUIRE) != td)
            continue;

        uint64_t old = __atomic_load_n(&latch->state, __ATOMIC_ACQUIRE);
        for(;;)
        {
            if(!(old & PPR_PFS_SESSION_PAIR_INFLIGHT))
                return 0;
            uint64_t next = old & ~PPR_PFS_SESSION_PAIR_INFLIGHT;
            if(syscall_failed)
                next &= ~PPR_PFS_SESSION_PAIR_OWNED;
            if(__atomic_compare_exchange_n(&latch->state, &old, next, 0,
                                           __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE))
            {
                if(!syscall_failed)
                {
                    if(remaining)
                        *remaining = __atomic_load_n(
                            &shared_area.ppr_plaintext_key_pairs_outstanding,
                            __ATOMIC_ACQUIRE);
                    return 1;
                }
                return release_ppr_plaintext_key_pair(remaining, NULL);
            }
        }
    }
    return 0;
}

static void forget_current_ppr_plaintext_key_pair(void)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td, __ATOMIC_ACQUIRE) == td)
        {
            __atomic_fetch_and(&latch->state,
                               ~(uint64_t)(PPR_PFS_SESSION_PAIR_OWNED
                                        | PPR_PFS_SESSION_PAIR_INFLIGHT),
                               __ATOMIC_ACQ_REL);
            return;
        }
    }
}

static void clear_current_ppr_plaintext_latch(int mount_failed)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td,
                           __ATOMIC_ACQUIRE) != td)
            continue;
        uint64_t state = __atomic_exchange_n(&latch->state, 0,
                                             __ATOMIC_ACQ_REL);
        if(mount_failed && (state & PPR_PFS_SESSION_PAIR_OWNED))
            (void)release_ppr_plaintext_key_pair(NULL, NULL);
        __atomic_store_n(&latch->td, 0,
                         __ATOMIC_RELEASE);
    }
    release_ppr_plaintext_staging(td);
}

int control_ppr_plaintext_request(uint64_t magic, uint64_t mode,
                                  uint64_t arg0, uint64_t arg1,
                                  uint64_t arg2, uint64_t arg3,
                                  uint64_t* result)
{
    /*
     * "PPRPLAIN", protocol v8. No user pointer is dereferenced: WRITE carries
     * 16 snapshot bytes in R8/R9. R10 is deliberately unused because the
     * established kekcall fast snapshot ends at RAX and includes R8/R9.
     */
    *result = 0;
    if(FWVER != 0x940 || magic != 0x505052504c41494eull)
        return EINVAL;
    uint64_t td = 0;
    if(get_current_ppr_thread(&td))
        return EFAULT;
    if(mode == 0)
    {
        if(arg0 != PPR_PLAINTEXT_PROTOCOL_VERSION)
            return EINVAL;
        /* R10 is not present in the established kekcall snapshot.  Protocol
         * v8 carries sceFsMountPprPkg's result in arg2/R8 instead. */
        clear_current_ppr_plaintext_latch(arg2 != 0);
        return 0;
    }
    if(mode == PPR_CONTROL_BEGIN)
    {
        if(arg0 != PPR_PLAINTEXT_PROTOCOL_VERSION)
            return EINVAL;
        return begin_current_ppr_plaintext_staging(td);
    }
    if(mode == PPR_CONTROL_WRITE)
        return write_current_ppr_plaintext_staging(
            td, arg0, arg1, arg2, arg3);
    if(mode == PPR_CONTROL_CHECK)
    {
        struct kstuff_ppr_plaintext_staging* staging =
            &shared_area.ppr_plaintext_staging;
        if(__atomic_load_n(&staging->td, __ATOMIC_ACQUIRE) != td)
            return EPERM;
        uint64_t failed = validate_ppr_plaintext_staging(staging);
        if(__atomic_load_n(&staging->bytes_written, __ATOMIC_ACQUIRE)
                                                   != PPR_STAGING_SIZE)
            failed |= 1ull << 8;
        *result = failed;
        return 0;
    }
    if(mode != PPR_PFS_CONTROL_PLAINTEXT_NOAUTH
    || arg0 != PPR_PLAINTEXT_PROTOCOL_VERSION)
        return EINVAL;

    struct kstuff_ppr_plaintext_staging* staging =
        &shared_area.ppr_plaintext_staging;
    if(__atomic_load_n(&staging->td, __ATOMIC_ACQUIRE) != td
    || __atomic_load_n(&staging->bytes_written, __ATOMIC_ACQUIRE)
                                                   != PPR_STAGING_SIZE
    || validate_ppr_plaintext_staging(staging))
    {
        release_ppr_plaintext_staging(td);
        return EINVAL;
    }
    __atomic_store_n(&staging->ready, 1, __ATOMIC_RELEASE);
    int armed = arm_current_ppr_plaintext_latch(&td);
    if(!armed)
        release_ppr_plaintext_staging(td);
    else
        METRIC_INC(ppr_plaintext_profile_matches);
#if KSTUFF_OBS
    log_word(0x50505241524d3038ull); /* "PPRARM08" */
    log_word(td);
    log_word(mode);
    log_word(armed);
    log_word(load_u64_unaligned(shared_area.ppr_plaintext_staging.fih));
    log_word(load_u64_unaligned(
        shared_area.ppr_plaintext_staging.superblock));
#endif
    return armed ? 0 : EBUSY;
}

static int current_ppr_plaintext_session_active(uint64_t* active_td)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return 0;
    if(active_td)
        *active_td = td;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        if(__atomic_load_n(&latch->td, __ATOMIC_ACQUIRE) == td
        && (__atomic_load_n(&latch->state, __ATOMIC_ACQUIRE)
            & PPR_PFS_SESSION_STATE_MASK) == PPR_PFS_SESSION_ACTIVE)
            return 1;
    }
    return 0;
}

static int current_ppr_plaintext_session_pending(void)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return 0;
    for(size_t i = 0; i < SHARED_PPR_PLAINTEXT_LATCH_SLOTS; i++)
    {
        struct kstuff_ppr_plaintext_latch* latch =
            &shared_area.ppr_plaintext_latches[i];
        uint64_t state = __atomic_load_n(&latch->state,
                                         __ATOMIC_ACQUIRE);
        if(__atomic_load_n(&latch->td, __ATOMIC_ACQUIRE) == td
        && ((state & PPR_PFS_SESSION_STATE_MASK) == PPR_PFS_SESSION_ARMED
         || (state & PPR_PFS_SESSION_STATE_MASK) == PPR_PFS_SESSION_ACTIVE))
            return 1;
    }
    return 0;
}

static void try_emulate_plaintext_key_index(uint64_t* regs, int cmac)
{
    METRIC_INC(ppr_plaintext_g6_traps);
    canonicalize_debug_gprs(regs);

    uint64_t active_td = 0;
    uint32_t expected_handle = cmac ? PPR_PFS_PLAINTEXT_CMAC_HANDLE
                                    : PPR_PFS_PLAINTEXT_XTS_HANDLE;
    /*
     * Translate the private handles to the positive FE/FF indices consumed by
     * A53.  A -1 encryption handle makes ppfs_read_outer_block select the
     * unsupported ppfs_read_nsid2_plain_icv path before A53 is reached.
     */
    uint32_t expected_index = cmac ? 0xfe : 0xff;
    uint64_t expected_return = (uint64_t)sceSblServiceMailbox
        - (cmac ? PPR_PFS_940_GET_CMAC_RETURN_BEFORE_MAILBOX
                : PPR_PFS_940_GET_XTS_RETURN_BEFORE_MAILBOX);
    uint64_t return_address = 0;
    if(!current_ppr_plaintext_session_active(&active_td)
    || (uint32_t)regs[RDI] != expected_handle
    || (regs[RSI] >> 48) != 0xffff
    || copy_u64_from_kernel(&return_address, regs[RSP])
    || return_address != expected_return)
    {
        METRIC_INC(ppr_plaintext_g6_bad_initial_indices);
        return;
    }
    if(copy_u32_to_kernel(regs[RSI], expected_index))
    {
        METRIC_INC(ppr_plaintext_g6_copy_failures);
        return;
    }

    regs[RSP] += sizeof(uint64_t);
    regs[RIP] = return_address;
    regs[RAX] = 0;
    METRIC_INC(ppr_plaintext_g6_applied);
    observe_current_syscall_emulated();
#if KSTUFF_OBS
    log_word(0x5050524b49445831ull); /* "PPRKIDX1" */
    log_word(cmac ? 1 : 2);
    log_word(active_td);
    log_word(return_address);
#endif
}

static void try_prepare_plaintext_key_cleanup(uint64_t* regs)
{
    uint64_t cleanup_context = 0;
    uint64_t key_indices = 0;
#if KSTUFF_OBS
    uint64_t xts_retained = 0;
    uint64_t cmac_retained = 0;
#endif
    const uint64_t synthetic_indices = 0x000000fe000000ffull;

    /* RF is set by the common kernel-trap path, so leave RIP at the original
     * entry and let the complete stock prologue execute after this handler.
     * This keeps unrelated native cleanup byte-for-byte native. */
    canonicalize_debug_gprs(regs);

    /*
     * a1[271] points at the transient ppfs cleanup context. XTS and CMAC
     * indices are adjacent dwords at +56/+60. They were never reserved in the
     * stock allocator, so convert only the exact FF/FE pair to its normal
     * "not installed" representation before the original cleanup tests it.
     */
    if(!has_ppr_plaintext_key_pair()
    || (regs[RDI] >> 48) != 0xffff
    || copy_u64_from_kernel(&cleanup_context,
                            regs[RDI] + 271 * sizeof(uint64_t)))
        return;
    cleanup_context = canonicalize_debug_kernel_pointer(cleanup_context);
    if((cleanup_context >> 48) != 0xffff
    || copy_u64_from_kernel(&key_indices, cleanup_context + 56)
    || key_indices != synthetic_indices)
        return;
    if(copy_u64_to_kernel(cleanup_context + 56, UINT64_MAX))
    {
        METRIC_INC(ppr_plaintext_g6_copy_failures);
        return;
    }

    /*
     * The original body now skips both ppfs_put_* calls and performs the rest
     * of its context/VFS teardown unchanged.  Do not release the retained
     * handles here: ppr_pfs_unmount subsequently calls sceSblPfsClearKey for
     * the FD/FC pair.  Its stock tree lookup must miss because the private
     * pair was never registered; the exact miss trap is the lifetime end of
     * both synthetic keys.
     */
    observe_current_syscall_emulated();
#if KSTUFF_OBS
    xts_retained = __atomic_load_n(
        &shared_area.ppr_plaintext_key_pairs_outstanding,
        __ATOMIC_ACQUIRE);
    cmac_retained = xts_retained;
    log_word(0x505052434c4e3031ull); /* "PPRCLN01" */
    log_word(cleanup_context);
    log_word(key_indices);
    log_word(xts_retained);
    log_word(cmac_retained);
#endif
}

static void try_emulate_plaintext_clear_key_missing(uint64_t* regs)
{
    const uint64_t expected_pair =
        ((uint64_t)PPR_PFS_PLAINTEXT_XTS_HANDLE << 32)
      | PPR_PFS_PLAINTEXT_CMAC_HANDLE;
    uint64_t xts_remaining = 0;
    uint64_t cmac_remaining = 0;
    uint64_t trap = ppr_pfs_plaintext_clear_key_missing();
    int expected_args = regs[R13] == expected_pair
                     || (regs[R14] == PPR_PFS_PLAINTEXT_XTS_HANDLE
                      && regs[R15] == PPR_PFS_PLAINTEXT_CMAC_HANDLE);

    /* At this point sceSblPfsClearKey has normally built (a1 << 32) | a2 in
     * R13 and still owns its normal lock/frame.  If the tree root itself is
     * null, the branch arrives before that construction and the original
     * zero-extended arguments remain in R14/R15, so accept that equivalent
     * exact shape too.  Unrelated misses execute the trapped stock instruction
     * through RF without register or RIP emulation.
     */
    if(!expected_args
    || !has_ppr_plaintext_key_pair())
    {
        /* RF lets the trapped stock `mov ebx, 0xfffffffe` execute once. */
        return;
    }
    if(!release_ppr_plaintext_key_pair(&xts_remaining, &cmac_remaining))
        return;
    /* An internal rollback unmount can run before the still-active ShellCore
     * mount wrapper reports failure.  Disown the pair so its final CLEAR does
     * not release a second, unrelated mount's global count. */
    forget_current_ppr_plaintext_key_pair();

    /*
     * Skip the diagnostic call but retain sceSblPfsClearKey's stock unlock,
     * stack-canary check and epilogue at loc_ffffffff953e041f.
     */
    regs[RBX] = 0;
    regs[RIP] = trap + 0x16;
    METRIC_INC(clear_key_emulated);
    observe_current_syscall_emulated();
#if KSTUFF_OBS
    log_word(0x505052434c523031ull); /* "PPRCLR01" */
    log_word(expected_pair);
    log_word(xts_remaining);
    log_word(cmac_remaining);
    log_word(regs[RIP]);
#endif
}


#define IDX_TO_HANDLE(x) (0x13374100 | ((uint8_t)((x)+1)))
#define HANDLE_TO_IDX(x) ((((x) & 0xffffff00) == 0x13374100 ? ((int)(uint8_t)(x)) : (int)0) - 1)

struct crypto_message_result
{
    int emulated_messages;
    uint64_t next_msg;
    int status;
    int total_messages;
};

enum crypto_message_kind
{
    CRYPTO_MESSAGE_OTHER,
    CRYPTO_MESSAGE_HMAC,
    CRYPTO_MESSAGE_XTS,
};

enum {
    CRYPTO_MESSAGE_DATA_QWORDS = 21,
    CRYPTO_MESSAGE_NEXT_OFFSET = 320,
};

struct crypto_message_info
{
    enum crypto_message_kind kind;
    int key_idx;
};

static struct crypto_request_cache s_crypto_request_cache;

static int crypto_request_emulated(uint64_t* regs, uint64_t msg, uint32_t status)
{
    uint64_t frame[7] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_FPKG, 1), 0, 0, 0, 0,
        0
    };
    if(push_stack_checked(regs, frame, sizeof(frame)))
        return 0;
    regs[RIP] = (uint64_t)crypt_message_resolve;
    regs[RDI] = msg;
    regs[RSI] = status;
    return 1;
}

static int read_crypto_message(uint64_t msg,
                               uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS],
                               uint64_t* next_msg)
{
    METRIC_INC(crypto_message_snapshot_reads);
    METRIC_TIME_START(start_cycles);
    int error = copy_from_kernel(msg_data, msg,
                                 sizeof(uint64_t) * CRYPTO_MESSAGE_DATA_QWORDS);
    if(!error)
        error = copy_u64_from_kernel(next_msg, msg + CRYPTO_MESSAGE_NEXT_OFFSET);
    if(error)
        METRIC_INC(crypto_message_snapshot_failures);
    METRIC_TIME(crypto_message_snapshot_cycles_total,
                crypto_message_snapshot_cycles_max, start_cycles);
    return error;
}

static int is_hmac_message(const uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS])
{
    return (msg_data[0] & 0x7fffffff) == 0x9132000;
}

static int is_xts_message(const uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS])
{
    return (msg_data[0] & 0x7ffff7ff) == 0x2108000;
}

static struct crypto_message_result unhandled_crypto_message(uint64_t next_msg)
{
    return (struct crypto_message_result){
        .emulated_messages = 0,
        .next_msg = next_msg,
        .status = ENOSYS,
        .total_messages = 1,
    };
}

static struct crypto_message_info inspect_crypto_message(
    const uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS], uint8_t key[32])
{
    if(is_xts_message(msg_data))
    {
        int key_idx = HANDLE_TO_IDX(msg_data[5]);
        if(key_idx < 0 || !get_fake_key(key_idx, key))
        {
            METRIC_INC(fpkg_reject_xts_non_fake);
        }
        else
        {
            struct crypto_message_info info = {
                .kind = CRYPTO_MESSAGE_XTS,
                .key_idx = key_idx,
            };
            return info;
        }
    }
    if(is_hmac_message(msg_data))
    {
        int key_idx = HANDLE_TO_IDX(msg_data[20]);
        if(msg_data[3] != msg_data[1] * 8)
        {
            METRIC_INC(fpkg_reject_hmac_bad_shape);
        }
        else if(key_idx < 0 || !get_fake_key(key_idx, key))
        {
            METRIC_INC(fpkg_reject_hmac_non_fake);
        }
        else
        {
            struct crypto_message_info info = {
                .kind = CRYPTO_MESSAGE_HMAC,
                .key_idx = key_idx,
            };
            return info;
        }
    }
    METRIC_INC(fpkg_reject_other_message);
    return (struct crypto_message_info){
        .kind = CRYPTO_MESSAGE_OTHER,
        .key_idx = -1,
    };
}

static struct crypto_message_result handle_hmac_message(uint64_t msg,
                                                        const uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS],
                                                        uint64_t next_msg,
                                                        int key_idx, const uint8_t key[32],
                                                        struct crypto_request_cache* cache)
{
    struct crypto_message_result result = unhandled_crypto_message(next_msg);
    uint8_t hash[32] = {0};
    if(pfs_hmac_virtual_fpu_held(cache, hash, key_idx, key, msg_data[2], msg_data[1]))
    {
        result.emulated_messages = 1;
        result.status = -1;
        return result;
    }
    if(copy_to_kernel(msg+32, hash, 32))
    {
        result.emulated_messages = 1;
        result.status = -1;
        return result;
    }
    result.emulated_messages = 1;
    result.status = 0;
    return result;
}

static struct crypto_message_result handle_xts_message(
    const uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS], uint64_t next_msg,
    int key_idx, const uint8_t key[32], struct crypto_request_cache* cache)
{
    struct crypto_message_result result = unhandled_crypto_message(next_msg);
    METRIC_INC(xts_run_messages_total);

    uint64_t src = msg_data[2];
    uint64_t dst = msg_data[3];
    uint64_t start_sector = msg_data[4];
    uint32_t total_sectors = (uint32_t)msg_data[1];
    int is_encrypt = (msg_data[0] & 0x800) >> 11;

    if(pfs_xts_virtual_fpu_held(cache, dst, src, key_idx, key, start_sector, total_sectors, is_encrypt))
    {
        result.emulated_messages = 1;
        result.status = -1;
        return result;
    }

    result.emulated_messages = 1;
    result.status = 0;
    return result;
}

/*
static inline uint64_t rdtsc(void)
{
    uint32_t a, d;
    asm volatile("rdtsc":"=a"(a),"=d"(d));
    return (uint64_t)d << 32 | a;
}
*/

static int handle_crypto_request(uint64_t* regs)
{
    METRIC_TIME_START(start_cycles);
    // uint64_t start_time = rdtsc();
    int total = 0;
    int emulated = 0;
    int total_status = 0;
    int handled = 0;
    int fpu_entered = 0;
    METRIC_INC(crypto_requests_total);

    /*
     * TODO(FW_PORT): at sceSblServiceCryptAsync's trap/call site, trace the
     * linked-list head argument into the saved register frame and update this
     * selection for the new firmware.  Validate it by walking several message
     * chains read-only before enabling emulation.
     */
    uint64_t start = (FWVER >= 0x800) ? regs[RBX] : regs[R14];

    for (uint64_t msg = start; msg && !total_status;)
    {
        uint64_t msg_data[CRYPTO_MESSAGE_DATA_QWORDS];
        uint64_t next_msg;
        if(read_crypto_message(msg, msg_data, &next_msg))
        {
            total_status = -1;
            break;
        }

        uint8_t key[32];
        struct crypto_message_info msg_info = inspect_crypto_message(msg_data, key);
        METRIC_INC(crypto_messages_total);
        if(msg_info.kind == CRYPTO_MESSAGE_XTS)
            METRIC_INC(crypto_messages_xts);
        else if(msg_info.kind == CRYPTO_MESSAGE_HMAC)
            METRIC_INC(crypto_messages_hmac);
        else
            METRIC_INC(crypto_messages_other);
        if(!fpu_entered && msg_info.kind != CRYPTO_MESSAGE_OTHER)
        {
            if(uelf_fpu_enter())
            {
                METRIC_INC(fpkg_request_fpu_enter_fail);
                break;
            }
            fpu_entered = 1;
        }

        struct crypto_message_result result;
        if(msg_info.kind == CRYPTO_MESSAGE_XTS)
            result = handle_xts_message(msg_data, next_msg, msg_info.key_idx, key,
                                        &s_crypto_request_cache);
        else if(msg_info.kind == CRYPTO_MESSAGE_HMAC)
            result = handle_hmac_message(msg, msg_data, next_msg,
                                         msg_info.key_idx, key,
                                         &s_crypto_request_cache);
        else
            result = unhandled_crypto_message(next_msg);
        int status = result.status;

        total += result.total_messages;

        if (status != ENOSYS)
        {
            emulated += result.emulated_messages;
            METRIC_ADD(crypto_emulated_messages, result.emulated_messages);
            if (status)
                total_status = status;
        }
        msg = result.next_msg;
    }

    if (emulated)
    {
        if (emulated < total)
        {
            // not all requests successfully emulated
            // we can't run only part of the request, so just report failure
            total_status = -1;
        }

        if(!crypto_request_emulated(regs, (FWVER >= 0x800) ? regs[RBX] : regs[R14], total_status))
            goto exit;
        METRIC_INC(crypto_requests_emulated);
        if(total_status)
            METRIC_INC(crypto_requests_failed);
        // uint64_t end_time = rdtsc();
        /*log_word(0x1234);
        log_word(end_time - start_time);*/
        handled = 1;
    }

exit:
    if(!handled)
    {
        METRIC_INC(crypto_requests_fallback);
        METRIC_INC(fpkg_request_no_emulation);
    }
    if(fpu_entered)
        uelf_fpu_exit();
    METRIC_TIME(fpkg_crypto_request_cycles_total, fpkg_crypto_request_cycles_max, start_cycles);
    return handled;
}

int is_fpkg_trap_rip(uint64_t rip)
{
    return rip == (uint64_t)sceSblServiceCryptAsync_deref_singleton
        || rip == ppr_pfs_plaintext_get_xts_index()
        || rip == ppr_pfs_plaintext_get_cmac_index()
        || rip == ppr_pfs_plaintext_cleanup_keys()
        || rip == ppr_pfs_plaintext_clear_key_missing();
}

int try_handle_fpkg_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblServiceCryptAsync_deref_singleton)
    {
        if(handle_crypto_request(regs))
            observe_current_syscall_emulated();
        else
        {
            regs[RAX] |= -1ull << 48;
            regs[RBX] |= -1ull << 48;
        }
    }
    else if(regs[RIP] == ppr_pfs_plaintext_get_xts_index())
    {
        try_emulate_plaintext_key_index(regs, 0);
    }
    else if(regs[RIP] == ppr_pfs_plaintext_get_cmac_index())
    {
        try_emulate_plaintext_key_index(regs, 1);
    }
    else if(regs[RIP] == ppr_pfs_plaintext_cleanup_keys())
    {
        try_prepare_plaintext_key_cleanup(regs);
    }
    else if(regs[RIP] == ppr_pfs_plaintext_clear_key_missing())
    {
        try_emulate_plaintext_clear_key_missing(regs);
    }
    else
        return 0;
    return 1;
}

int try_handle_fpkg_mailbox(uint64_t* regs, uint64_t lr)
{
    uint64_t ppr_verify_image_lr = ppr_pfs_verify_image_lr();
    int is_ppr_verify_image = ppr_verify_image_lr && lr == ppr_verify_image_lr;

    if(lr == (uint64_t)sceSblServiceMailbox_lr_verifySuperBlock
    || is_ppr_verify_image)
    {
        METRIC_INC(verify_superblock_mailbox);
        /* DR delivery may poison the high pointer bits in saved GPRs. */
        if(is_ppr_verify_image)
            canonicalize_debug_gprs(regs);
        uint64_t req[13] = {0};
        if(copy_from_kernel(req, regs[RDX], 64))
            return 0;
        if(is_ppr_verify_image && (req[0] != 1 || req[3] != 0x20000))
            return 0;
        if(is_ppr_verify_image
        && copy_from_kernel(req + 8, regs[RDX] + 64,
                            sizeof(req) - 64))
            return 0;

        uint64_t fih_read_size = 0;
        uint64_t sblock_input_size = 0;
        uint64_t output_request_size = 0;
        uint64_t output_capacity = 0;
        int ppr_request_malformed = 0;
        int ppr_plaintext_pending = is_ppr_verify_image
                                  && current_ppr_plaintext_session_pending();
        if(ppr_plaintext_pending)
        {
            /* req[9] is { FIH output size, superblock output capacity }. */
            fih_read_size = (uint32_t)req[9];
            sblock_input_size = req[9] >> 32;
            int output_size_error = copy_u64_from_kernel(
                                        &output_request_size,
                                        regs[RBP] - 0x160);
            if(!output_size_error
            && output_request_size <= UINT64_MAX - 0x3fff)
                output_capacity = (output_request_size + 0x3fff)
                                & ~0x3fffull;
            else
                output_size_error = EINVAL;
            ppr_request_malformed = output_size_error
                                 || (regs[R13] >> 48) != 0xffff
                                 || (regs[R14] >> 48) != 0xffff
                                 || (regs[R15] >> 48) != 0xffff
                                 || fih_read_size != PPR_FIH_SIZE
                                 || sblock_input_size != 0x3000
                                 || !output_request_size
                                 || output_request_size > 0x20000
                                 || output_capacity < fih_read_size
                                 || output_capacity > 0x20000;
        }
        uint64_t latch_td = 0;
        int ppr_plaintext_latched = ppr_plaintext_pending
                                  && !ppr_request_malformed
                                  && consume_current_ppr_plaintext_latch(
                                         &latch_td);
#if KSTUFF_OBS
        if(is_ppr_verify_image)
        {
            log_word(0x5050524d42583331ull); /* "PPRMBX31" */
            log_word(lr);
            log_word(ppr_verify_image_lr);
            log_word(latch_td);
            log_word(ppr_plaintext_latched);
            log_word(ppr_request_malformed);
        }
#endif

        /*
         * The legacy path enters through verifySuperBlock.  PPR on 9.40
         * instead enters through verifyImage at a distinct return address.
         * For an explicitly armed PLAINTEXT_NOAUTH profile the secure module
         * is intentionally not entered:
         * return its normal success shape with two distinct sentinel handles
         * and both completed read sizes. sm_pfs normally uses the vnode/FIH
         * context in request qwords 10/11 to read and fill a 0x1000-byte FIH
         * buffer plus a 0x5a0-byte verified superblock. Calling VFS from the
         * debug exception is unsafe, so protocol v8 snapshots both file ranges
         * before nmount and this trap supplies the same output buffers.
         * registerMountKey indexes a global RB tree by handle alone.  The
         * emulated result therefore jumps past both key registrations and the
         * pair-tree insertion: the sentinels never enter either global table.
         * A retained-pair counter lets the later unmount trap complete the
         * matching sceSblPfsClearKey tree miss without touching unrelated
         * pairs.
         * The kernel-side verify_ppr_sblock_100 continuation still checks the
         * returned read sizes and parses the superblock metadata. Later in the
         * same nmount, exact ppfs_get_{xts,cmac}_index entry traps return the
         * positive sentinel indices ff/fe without allocating nonexistent keys. A53 sees
         * the retained pair as the private fe/ff request marker and diverts
         * the request to plaintext IDMA before either index can be used as a
         * real key.
         *
         * The FIH geometry, tweak, NAPS metadata offsets and the superblock
         * remain the bytes from the package.  This is required even without
         * authentication: the kernel derives its outer ICV/fsmeta table
         * geometry from FIH +0x90 before any read request reaches A53.
         * verifySuperBlock keeps its established DMEM layout. At the 9.40
         * verifyImage mailbox call the secure-module output buffers have not
         * been filled yet, so the exact LR, request shape and one-shot
         * same-thread latch are all required.
         * The active same-thread session authorizes only the two exact sentinel
         * key-index calls from setup_a53io_pkg_keys and is explicitly cleared
         * by ppr_mount after sceFsMountPprPkg returns.
         */
        uint16_t pfs_mode = 0;
        int mode_error = 0;
        if(is_ppr_verify_image)
        {
            if(ppr_plaintext_latched)
                pfs_mode = PPR_PFS_CONTROL_PLAINTEXT_NOAUTH;
            else
                mode_error = EPERM;
        }
        else
        {
            memcpy(&pfs_mode, DMEM+req[3]+0x1c, sizeof(pfs_mode));
        }
        if(!mode_error && FWVER == 0x940
        && pfs_mode == PPR_PFS_CONTROL_PLAINTEXT_NOAUTH)
        {
            /* sm_pfs command 0x0001 returns the fixed verified header size. */
            const uint64_t sblock_read_size = 0x5a0;
            struct kstuff_ppr_plaintext_staging* staging =
                &shared_area.ppr_plaintext_staging;
#if KSTUFF_OBS
            uint64_t staged_fih_magic = load_u64_unaligned(staging->fih);
            uint64_t staged_sblock_header =
                load_u64_unaligned(staging->superblock);
#endif
            int copy_error = ppr_request_malformed ? EINVAL : 0;
            int pair_retained = 0;
            if(!copy_error
            && (__atomic_load_n(&staging->td, __ATOMIC_ACQUIRE) != latch_td
             || !__atomic_load_n(&staging->ready, __ATOMIC_ACQUIRE)))
                copy_error = EPERM;
            if(!copy_error)
            {
                pair_retained = retain_current_ppr_plaintext_key_pair(latch_td);
                if(!pair_retained)
                    copy_error = EBUSY;
            }
            if(!copy_error)
                copy_error = zero_kernel_checked(regs[R13], fih_read_size);
            if(!copy_error)
                copy_error = copy_to_kernel(regs[R13], staging->fih,
                                             sizeof(staging->fih));
            /*
             * Keep the FIH block geometry at +0x90 intact.  Clearing it makes
             * set_icv_table publish offset=0 and rejects metadata LBNs in the
             * kernel before they reach the A53 no-auth selector.
             */
            if(!copy_error)
                copy_error = zero_kernel_checked(regs[R14],
                                                  sblock_input_size);
            if(!copy_error)
                copy_error = copy_to_kernel(regs[R14], staging->superblock,
                                             sblock_read_size);
            /* Keep the staged, marker-bearing mode 0x0d on the stock path. */
            if(!copy_error)
                copy_error = copy_u16_to_kernel(
                    regs[R14] + 0x1c, PPR_PFS_MODE_NATIVE_ENCRYPTED);
            if(!copy_error)
                copy_error = zero_kernel_checked(regs[R15], fih_read_size);
#if KSTUFF_OBS
            log_word(0x50505256494d4736ull); /* "PPRVIM6" */
            log_word(regs[R13]);             /* FIH output */
            log_word(regs[R14]);             /* superblock output */
            log_word(regs[R15]);             /* ICV-keep output */
            log_word(req[9]);
            log_word((output_request_size << 32) | output_capacity);
            log_word(copy_error);
            log_word(staged_fih_magic);
            log_word(staged_sblock_header);
#endif
            if(copy_error)
            {
                if(pair_retained)
                    (void)finish_current_ppr_plaintext_key_pair(
                        latch_td, 1, NULL);
                return 0;
            }

            struct
            {
                uint32_t command;
                uint32_t status;
                uint32_t ekey;
                uint32_t skey;
                uint64_t fih_read_size;
                uint64_t sblock_read_size;
            } fake_resp = {
                .command = 0,
                .status = 0,
                .ekey = PPR_PFS_PLAINTEXT_XTS_HANDLE,
                .skey = PPR_PFS_PLAINTEXT_CMAC_HANDLE,
                .fih_read_size = fih_read_size,
                .sblock_read_size = sblock_read_size,
            };
            _Static_assert(sizeof(fake_resp) == 32,
                           "unexpected verifyImage response layout");
            /*
             * Recreate the two values that the skipped 9.40 wrapper code
             * would have prepared, then continue at loc_953df2dc.  That block
             * combines the pair and publishes both completed read sizes.  We
             * enter it after (and deliberately without executing)
             * registerMountKey() or the pair RB-tree insertion.
             */
            if(copy_u64_to_kernel(regs[RBP] - 0x150,
                                  PPR_PFS_PLAINTEXT_XTS_HANDLE))
            {
                (void)finish_current_ppr_plaintext_key_pair(latch_td, 1,
                                                            NULL);
                return 0;
            }
            /*
             * Publish the mailbox response last.  If the stack-local write
             * fails, the stock secure-module call can still run without
             * observing a partially forged response header.
             */
            if(copy_to_kernel(regs[RDX], &fake_resp, sizeof(fake_resp)))
            {
                (void)finish_current_ppr_plaintext_key_pair(latch_td, 1,
                                                            NULL);
                return 0;
            }
            regs[R13] = PPR_PFS_PLAINTEXT_CMAC_HANDLE;
            release_ppr_plaintext_staging(latch_td);
            regs[RIP] = lr
                      + PPR_PFS_940_VERIFY_IMAGE_NO_KEY_SUCCESS_FROM_LR;
            regs[RAX] = 0;
            regs[RSP] += 8;
            METRIC_INC(verify_superblock_emulated);
            observe_current_syscall_emulated();
            return 1;
        }

        /* The PPR command has a different request layout from verifySuperBlock. */
        if(is_ppr_verify_image)
            return 0;

        uint64_t p_eekpfs = 0;
        memcpy(&p_eekpfs, DMEM+req[2]+32, 8);
        uint8_t eekpfs[256] = {0};
        memcpy(eekpfs, DMEM+p_eekpfs, 256);
        uint8_t crypt_seed[16];
        memcpy(crypt_seed, DMEM+req[3]+0x370, 16);
        uint8_t ek[32] = {}, sk[32] = {};
        if(pfs_derive_fake_keys(eekpfs, crypt_seed, ek, sk))
        {
            int key1 = register_fake_key(ek);
            if(key1 >= 0)
            {
                int key2 = register_fake_key(sk);
                if(key2 >= 0)
                {
                    uint32_t fake_resp[4] = {0, 0, IDX_TO_HANDLE(key1), IDX_TO_HANDLE(key2)};
                    if(copy_to_kernel(regs[RDX], fake_resp, sizeof(fake_resp)))
                    {
                        unregister_fake_key(key2);
                        unregister_fake_key(key1);
                        return 0;
                    }
                    regs[RIP] = lr;
                    regs[RAX] = 0;
                    regs[RSP] += 8;
                    METRIC_INC(verify_superblock_emulated);
                    observe_current_syscall_emulated();
                }
                else
                    unregister_fake_key(key1);
            }
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_sceSblPfsClearKey_1
         || lr == (uint64_t)sceSblServiceMailbox_lr_sceSblPfsClearKey_2)
    {
        METRIC_INC(clear_key_mailbox);
        uint32_t handle;
        if(copy_u32_from_kernel(&handle, regs[RDX] + 8))
            return 0;

        int key = HANDLE_TO_IDX(handle);
        if(key >= 0)
        {
            if(copy_to_kernel(regs[RDX], (const uint64_t[16]){}, 16))
                return 0;
            if(!unregister_fake_key(key))
                return 0;
            regs[RIP] = lr;
            regs[RAX] = 0;
            regs[RSP] += 8;
            METRIC_INC(clear_key_emulated);
            observe_current_syscall_emulated();
        }
    }
    /*else
    {
        uint64_t req[2];
        copy_from_kernel(req, regs[RDX], sizeof(req));
        if((uint32_t)req[0] == 3)
        {
            log_word(0x4141414141414141);
            log_word(req[0]);
            log_word(req[1]);
            int key = HANDLE_TO_IDX(req[1]);
            log_word(key);
            if(key >= 0 && unregister_fake_key(key))
            {
                log_word(0x4141414141414142);
                log_word(lr);
                copy_to_kernel(regs[RDX], (const uint64_t[16]){}, 128);
                regs[RIP] = lr;
                regs[RAX] = 0;
                regs[RSP] += 8;
                return 1;
            }
        }
        return 0;
    }*/
    else
        return 0;
    return 1;
}

void handle_fpkg_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        enum { FRAME_QWORDS = 12, TAIL_OFFSET_QWORDS = 7 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        regs[RBX] = tail[0];
        regs[R14] = tail[1];
        regs[R15] = tail[2];
        regs[RBP] = tail[3];
        regs[RIP] = tail[4];
        regs[RAX] = 0;
    }
}

void finish_fpkg_syscall(uint64_t* regs)
{
    uint64_t td;
    if(get_current_ppr_thread(&td))
        return;

    /* This trap runs immediately after sy_call returns and before syscall_after
     * translates its integer errno to the userspace CF convention.  Only the
     * nmount that actually forged a key pair has INFLIGHT set, so other nmount
     * and unmount completions are no-ops here. */
    int syscall_failed = (uint32_t)regs[RAX] != 0;
    uint64_t remaining = 0;
    int finished = finish_current_ppr_plaintext_key_pair(
        td, syscall_failed, &remaining);
#if KSTUFF_OBS
    if(finished)
    {
        log_word(0x50505246494e3031ull); /* "PPRFIN01" */
        log_word(td);
        log_word(syscall_failed);
        log_word(remaining);
    }
#else
    (void)finished;
    (void)remaining;
#endif
}

void handle_fpkg_syscall(uint64_t* regs, int is_nmount)
{
    uint64_t dbgregs_for_fpkg[6] = {
        (uint64_t)sceSblServiceMailbox, 0, 0, 0,
        0, 0x401
    };
    /*
     * Native nmount must keep its original debug-register footprint.  Arm
     * the two 9.40 key-index entry breakpoints only for the same thread that
     * explicitly owns an ARMED/ACTIVE PLAINTEXT_NOAUTH session; verifyImage
     * changes ARMED to ACTIVE later during this syscall.
     */
    int enable_ppr_plaintext_traps = is_nmount
                                  && current_ppr_plaintext_session_pending();
    uint64_t get_xts = enable_ppr_plaintext_traps
                     ? ppr_pfs_plaintext_get_xts_index() : 0;
    uint64_t get_cmac = enable_ppr_plaintext_traps
                      ? ppr_pfs_plaintext_get_cmac_index() : 0;
    uint64_t cleanup_keys = ppr_pfs_plaintext_cleanup_keys();
    uint64_t clear_key_missing = ppr_pfs_plaintext_clear_key_missing();
    if(get_xts && get_cmac && cleanup_keys)
    {
        dbgregs_for_fpkg[1] = cleanup_keys;
        dbgregs_for_fpkg[2] = get_xts;
        dbgregs_for_fpkg[3] = get_cmac;
        /* A later mount failure can clean the pair inside this same nmount. */
        dbgregs_for_fpkg[5] = 0x455; /* local DR0..DR3 + reserved bit 10 */
    }
    else if(!is_nmount && cleanup_keys && clear_key_missing
         && has_ppr_plaintext_key_pair())
    {
        dbgregs_for_fpkg[1] = cleanup_keys;
        dbgregs_for_fpkg[2] = clear_key_missing;
        dbgregs_for_fpkg[5] = 0x415; /* local DR0..DR2 + reserved bit 10 */
    }
    start_syscall_with_dbgregs(regs, dbgregs_for_fpkg);
}
