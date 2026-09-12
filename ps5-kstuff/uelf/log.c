#include "log.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"

#if KSTUFF_OBS
static struct
{
    enum kstuff_syscall_tag tag;
    int trap_reported;
    int emu_reported;
} s_current_syscall_state;

static inline void log_spin_pause(void)
{
    __asm__ volatile("pause");
}

static inline void spin_lock_u64(uint64_t* lock)
{
    while(__atomic_exchange_n(lock, 1, __ATOMIC_ACQ_REL))
        log_spin_pause();
}

static inline void spin_unlock_u64(uint64_t* lock)
{
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static struct kstuff_ioctl_com_entry* find_tracked_ioctl_com_entry(uint64_t com)
{
    for(size_t i = 0; i < SHARED_IOCTL_COM_TRACK_CAP; i++)
    {
        struct kstuff_ioctl_com_entry* entry = &shared_area.ioctl_com_table.entries[i];
        uint64_t seen = __atomic_load_n(&entry->com, __ATOMIC_ACQUIRE);
        if(!seen)
            break;
        if(seen == com)
            return entry;
    }
    return NULL;
}

static struct kstuff_ioctl_com_entry* find_or_add_ioctl_com_entry_locked(uint64_t com)
{
    struct kstuff_ioctl_com_entry* empty = NULL;

    for(size_t i = 0; i < SHARED_IOCTL_COM_TRACK_CAP; i++)
    {
        struct kstuff_ioctl_com_entry* entry = &shared_area.ioctl_com_table.entries[i];
        if(entry->com == com)
            return entry;
        if(!entry->com && !empty)
            empty = entry;
    }

    if(empty)
    {
        memset(empty, 0, sizeof(*empty));
        __atomic_store_n(&empty->com, com, __ATOMIC_RELEASE);
        return empty;
    }

    shared_area.ioctl_com_table.overflows++;
    return NULL;
}

static void snapshot_ioctl_com_table(struct kstuff_ioctl_com_table* out)
{
    spin_lock_u64(&shared_area.ioctl_com_table.write_lock);
    memcpy(out, &shared_area.ioctl_com_table, sizeof(*out));
    out->write_lock = 0;
    spin_unlock_u64(&shared_area.ioctl_com_table.write_lock);
}

static void observe_syscall_metric(enum kstuff_syscall_tag tag, int kind)
{
#define OBS_CASE(tag_name, armed_field, trap_field, emu_field) \
    case tag_name: \
        if(kind == 0) METRIC_INC(armed_field); \
        else if(kind == 1) METRIC_INC(trap_field); \
        else METRIC_INC(emu_field); \
        break
    switch(tag)
    {
    OBS_CASE(KSTUFF_SYSCALL_EXECVE, syscall_execve_armed, syscall_execve_trap, syscall_execve_emulated);
    OBS_CASE(KSTUFF_SYSCALL_DYNLIB_LOAD_PRX, syscall_dynlib_load_prx_armed, syscall_dynlib_load_prx_trap, syscall_dynlib_load_prx_emulated);
    OBS_CASE(KSTUFF_SYSCALL_GET_SELF_AUTH_INFO, syscall_get_self_auth_info_armed, syscall_get_self_auth_info_trap, syscall_get_self_auth_info_emulated);
    OBS_CASE(KSTUFF_SYSCALL_GET_SDK_COMPILED_VERSION, syscall_get_sdk_compiled_version_armed, syscall_get_sdk_compiled_version_trap, syscall_get_sdk_compiled_version_emulated);
    OBS_CASE(KSTUFF_SYSCALL_GET_PPR_SDK_COMPILED_VERSION, syscall_get_ppr_sdk_compiled_version_armed, syscall_get_ppr_sdk_compiled_version_trap, syscall_get_ppr_sdk_compiled_version_emulated);
    OBS_CASE(KSTUFF_SYSCALL_MMAP, syscall_mmap_armed, syscall_mmap_trap, syscall_mmap_emulated);
    OBS_CASE(KSTUFF_SYSCALL_MLOCK, syscall_mlock_armed, syscall_mlock_trap, syscall_mlock_emulated);
    OBS_CASE(KSTUFF_SYSCALL_NMOUNT, syscall_nmount_armed, syscall_nmount_trap, syscall_nmount_emulated);
    OBS_CASE(KSTUFF_SYSCALL_UNMOUNT, syscall_unmount_armed, syscall_unmount_trap, syscall_unmount_emulated);
    OBS_CASE(KSTUFF_SYSCALL_IOCTL, syscall_ioctl_armed, syscall_ioctl_trap, syscall_ioctl_emulated);
    OBS_CASE(KSTUFF_SYSCALL_MPROTECT, syscall_mprotect_armed, syscall_mprotect_trap, syscall_mprotect_emulated);
    OBS_CASE(KSTUFF_SYSCALL_MDBG_CALL, syscall_mdbg_call_armed, syscall_mdbg_call_trap, syscall_mdbg_call_emulated);
    default:
        break;
    }
#undef OBS_CASE
}

void log_word(uint64_t word)
{
    uint64_t seq = __atomic_fetch_add(&shared_area.word_log.next_seq, 1, __ATOMIC_RELAXED);
    struct kstuff_word_log_entry* entry = &shared_area.word_log.entries[seq % SHARED_LOG_WORD_CAP];
    __atomic_store_n(&entry->seq, 0, __ATOMIC_RELAXED);
    entry->word = word;
    __atomic_store_n(&entry->seq, seq + 1, __ATOMIC_RELEASE);
    METRIC_INC(log_word_writes);
}

void log_msg(const char* msg)
{
    if(!msg)
        return;
    size_t len = strlen(msg);
    if(!len)
        return;
    if(len > SHARED_LOG_MSG_CAP)
    {
        msg += len - SHARED_LOG_MSG_CAP;
        len = SHARED_LOG_MSG_CAP;
    }
    spin_lock_u64(&shared_area.msg_log.write_lock);
    uint64_t seq = shared_area.msg_log.next_seq;
    size_t off = seq % SHARED_LOG_MSG_CAP;
    size_t first = SHARED_LOG_MSG_CAP - off;
    if(first > len)
        first = len;
    memcpy(shared_area.msg_log.bytes + off, msg, first);
    if(len > first)
        memcpy(shared_area.msg_log.bytes, msg + first, len - first);
    __atomic_store_n(&shared_area.msg_log.next_seq, seq + len, __ATOMIC_RELEASE);
    spin_unlock_u64(&shared_area.msg_log.write_lock);
    METRIC_INC(log_msg_writes);
    METRIC_ADD(log_msg_bytes, len);
}

void observe_ioctl_com_emulated(uint64_t com, uint32_t cmd)
{
    spin_lock_u64(&shared_area.ioctl_com_table.write_lock);
    struct kstuff_ioctl_com_entry* entry = find_or_add_ioctl_com_entry_locked(com);
    if(entry)
    {
        if(!entry->total_hits)
            entry->total_hits = 1;
        entry->emulated_hits++;
        if(cmd == 5)
            entry->cmd5_hits++;
        else if(cmd == 6)
            entry->cmd6_hits++;
    }
    spin_unlock_u64(&shared_area.ioctl_com_table.write_lock);
}

void observe_ioctl_com_total(uint64_t com)
{
    struct kstuff_ioctl_com_entry* entry = find_tracked_ioctl_com_entry(com);
    if(entry)
        __atomic_fetch_add(&entry->total_hits, 1, __ATOMIC_RELAXED);
}

void observe_syscall_armed(enum kstuff_syscall_tag tag)
{
    s_current_syscall_state.tag = tag;
    s_current_syscall_state.trap_reported = 0;
    s_current_syscall_state.emu_reported = 0;
    observe_syscall_metric(tag, 0);
}

void observe_current_syscall_trap(void)
{
    if(s_current_syscall_state.tag != KSTUFF_SYSCALL_NONE
    && !s_current_syscall_state.trap_reported)
    {
        s_current_syscall_state.trap_reported = 1;
        observe_syscall_metric(s_current_syscall_state.tag, 1);
    }
}

void observe_current_syscall_emulated(void)
{
    if(s_current_syscall_state.tag != KSTUFF_SYSCALL_NONE
    && !s_current_syscall_state.emu_reported)
    {
        s_current_syscall_state.emu_reported = 1;
        observe_syscall_metric(s_current_syscall_state.tag, 2);
    }
}

void observe_current_syscall_finish(void)
{
    s_current_syscall_state.tag = KSTUFF_SYSCALL_NONE;
    s_current_syscall_state.trap_reported = 0;
    s_current_syscall_state.emu_reported = 0;
}

static int virt2phys_untracked(uint64_t addr, uint64_t* phys, uint64_t* phys_limit)
{
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12)))
            return 0;
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
            return 0;
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
    return 0;
}

static int copy_to_kernel_untracked(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    uint64_t phys, phys_end;
    while(sz)
    {
        if(!virt2phys_untracked(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM + phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

static void snapshot_metrics(struct kstuff_metrics* out)
{
    const uint64_t* src = (const uint64_t*)&shared_area.metrics;
    uint64_t* dst = (uint64_t*)out;
    for(size_t i = 0; i < sizeof(*out) / sizeof(uint64_t); i++)
        dst[i] = __atomic_load_n(&src[i], __ATOMIC_RELAXED);
}

static void snapshot_word_log_entry(struct kstuff_word_log_entry* out, size_t idx)
{
    for(;;)
    {
        uint64_t seq1 = __atomic_load_n(&shared_area.word_log.entries[idx].seq, __ATOMIC_ACQUIRE);
        if(!seq1)
        {
            out->seq = 0;
            out->word = 0;
            return;
        }
        out->word = shared_area.word_log.entries[idx].word;
        uint64_t seq2 = __atomic_load_n(&shared_area.word_log.entries[idx].seq, __ATOMIC_ACQUIRE);
        if(seq1 == seq2)
        {
            out->seq = seq2;
            return;
        }
    }
}

static void snapshot_word_log(struct kstuff_word_log* out)
{
    out->next_seq = __atomic_load_n(&shared_area.word_log.next_seq, __ATOMIC_ACQUIRE);
    for(size_t i = 0; i < SHARED_LOG_WORD_CAP; i++)
        snapshot_word_log_entry(&out->entries[i], i);
}

static void snapshot_msg_log(struct kstuff_msg_log* out)
{
    for(;;)
    {
        if(__atomic_load_n(&shared_area.msg_log.write_lock, __ATOMIC_ACQUIRE))
        {
            log_spin_pause();
            continue;
        }
        uint64_t seq1 = __atomic_load_n(&shared_area.msg_log.next_seq, __ATOMIC_ACQUIRE);
        memcpy(out->bytes, shared_area.msg_log.bytes, sizeof(out->bytes));
        if(!__atomic_load_n(&shared_area.msg_log.write_lock, __ATOMIC_ACQUIRE))
        {
            out->write_lock = 0;
            out->next_seq = seq1;
            return;
        }
    }
}

int copy_shared_area_snapshot(uint64_t dst, uint64_t sz)
{
    if(sz < sizeof(struct kstuff_snapshot))
        return EINVAL;

    struct
    {
        uint64_t bitmask;
        uint64_t ready_mask;
        struct kstuff_metrics metrics;
    } header;
    struct kstuff_word_log word_log;
    struct kstuff_ioctl_com_table ioctl_com_table;
    struct kstuff_msg_log msg_log;

    header.bitmask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    header.ready_mask = __atomic_load_n(&shared_area.ready_mask, __ATOMIC_ACQUIRE);
    snapshot_metrics(&header.metrics);
    snapshot_word_log(&word_log);
    snapshot_ioctl_com_table(&ioctl_com_table);
    snapshot_msg_log(&msg_log);

    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, bitmask), &header, sizeof(header)))
        return EFAULT;
    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, word_log), &word_log, sizeof(word_log)))
        return EFAULT;
    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, ioctl_com_table), &ioctl_com_table, sizeof(ioctl_com_table)))
        return EFAULT;
    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, msg_log), &msg_log, sizeof(msg_log)))
        return EFAULT;
    uint64_t ppr_key_pairs = __atomic_load_n(
        &shared_area.ppr_plaintext_key_pairs_outstanding, __ATOMIC_ACQUIRE);
    if(copy_to_kernel_untracked(
            dst + offsetof(struct kstuff_snapshot,
                           ppr_plaintext_key_pairs_outstanding),
            &ppr_key_pairs, sizeof(ppr_key_pairs)))
        return EFAULT;
    return 0;
}

#endif
