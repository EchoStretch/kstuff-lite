#pragma once

#include <stdint.h>

#ifndef KSTUFF_OBS
#define KSTUFF_OBS 0
#endif

enum {
    SHARED_AREA_SIZE = 8192,
    SHARED_FAKE_KEY_SLOTS = 63,
    SHARED_LOG_WORD_CAP = 16,
    SHARED_LOG_MSG_CAP = 488,
    SHARED_IOCTL_COM_TRACK_CAP = 128,
};

struct kstuff_metrics
{
    uint64_t handle_entries;
    uint64_t handle_from_userspace_entries;
    uint64_t handle_doreti_iret_entries;
    uint64_t debug_reg_decrypt_events;
    uint64_t debug_reg_decrypt_rax;
    uint64_t debug_reg_decrypt_rcx;
    uint64_t debug_reg_decrypt_rdx;
    uint64_t debug_reg_decrypt_rbx;
    uint64_t debug_reg_decrypt_rbp;
    uint64_t debug_reg_decrypt_rsi;
    uint64_t debug_reg_decrypt_rdi;
    uint64_t debug_reg_decrypt_r8;
    uint64_t debug_reg_decrypt_r9;
    uint64_t debug_reg_decrypt_r10;
    uint64_t debug_reg_decrypt_r11;
    uint64_t debug_reg_decrypt_r12;
    uint64_t debug_reg_decrypt_r13;
    uint64_t debug_reg_decrypt_r14;
    uint64_t debug_reg_decrypt_r15;
    uint64_t debug_reg_decrypt_rsi_only_events;
    uint64_t debug_reg_decrypt_rsi_multi_events;
    uint64_t debug_reg_decrypt_non_rsi_single_events;
    uint64_t debug_reg_decrypt_non_rsi_multi_events;
    uint64_t debug_unhandled_traps;
    uint64_t mailbox_traps;
    uint64_t mailbox_fself;
    uint64_t mailbox_fpkg;
    uint64_t mailbox_npdrm;
    uint64_t mailbox_unhandled;
    uint64_t fself_traps;
    uint64_t fpkg_traps;
    uint64_t syscall_fix_traps;
    uint64_t syscall_kekcall_dispatches;
    uint64_t syscall_fself_dispatches;
    uint64_t syscall_fpkg_dispatches;
    uint64_t syscall_ioctl_dispatches;
    uint64_t syscall_fix_dispatches;

    uint64_t handle_cycles_total;
    uint64_t handle_cycles_max;
    uint64_t handle_syscall_cycles_total;
    uint64_t handle_syscall_cycles_max;
    uint64_t generic_decrypt_cycles_total;
    uint64_t generic_decrypt_cycles_max;
    uint64_t fpkg_crypto_request_cycles_total;
    uint64_t fpkg_crypto_request_cycles_max;
    uint64_t npdrm_mailbox_cycles_total;
    uint64_t npdrm_mailbox_cycles_max;
    uint64_t xts_cycles_total;
    uint64_t xts_cycles_max;
    uint64_t virt2phys_cycles_total;
    uint64_t virt2phys_cycles_max;
    uint64_t copy_from_cycles_total;
    uint64_t copy_from_cycles_max;
    uint64_t copy_to_cycles_total;
    uint64_t copy_to_cycles_max;
    uint64_t syscall_execve_armed;
    uint64_t syscall_execve_trap;
    uint64_t syscall_execve_emulated;
    uint64_t syscall_dynlib_load_prx_armed;
    uint64_t syscall_dynlib_load_prx_trap;
    uint64_t syscall_dynlib_load_prx_emulated;
    uint64_t syscall_get_self_auth_info_armed;
    uint64_t syscall_get_self_auth_info_trap;
    uint64_t syscall_get_self_auth_info_emulated;
    uint64_t syscall_get_sdk_compiled_version_armed;
    uint64_t syscall_get_sdk_compiled_version_trap;
    uint64_t syscall_get_sdk_compiled_version_emulated;
    uint64_t syscall_get_ppr_sdk_compiled_version_armed;
    uint64_t syscall_get_ppr_sdk_compiled_version_trap;
    uint64_t syscall_get_ppr_sdk_compiled_version_emulated;
    uint64_t syscall_mmap_armed;
    uint64_t syscall_mmap_trap;
    uint64_t syscall_mmap_emulated;
    uint64_t syscall_mlock_armed;
    uint64_t syscall_mlock_trap;
    uint64_t syscall_mlock_emulated;
    uint64_t syscall_nmount_armed;
    uint64_t syscall_nmount_trap;
    uint64_t syscall_nmount_emulated;
    uint64_t syscall_unmount_armed;
    uint64_t syscall_unmount_trap;
    uint64_t syscall_unmount_emulated;
    uint64_t syscall_ioctl_armed;
    uint64_t syscall_ioctl_trap;
    uint64_t syscall_ioctl_emulated;
    uint64_t syscall_mprotect_armed;
    uint64_t syscall_mprotect_trap;
    uint64_t syscall_mprotect_emulated;
    uint64_t syscall_mdbg_call_armed;
    uint64_t syscall_mdbg_call_trap;
    uint64_t syscall_mdbg_call_emulated;

    uint64_t fself_header_cache_hits;
    uint64_t fself_header_cache_misses;
    uint64_t fself_context_cache_hits;
    uint64_t fself_context_cache_misses;
    uint64_t fself_header_parse_fself;
    uint64_t fself_header_parse_not_fself;
    uint64_t fself_header_parse_failures;
    uint64_t fself_authinfo_loads;
    uint64_t fself_authinfo_found;
    uint64_t fself_mailbox_verify_header;
    uint64_t fself_mailbox_verify_header_emulated;
    uint64_t fself_mailbox_load_self_segment;
    uint64_t fself_mailbox_load_self_segment_emulated;
    uint64_t fself_mailbox_decrypt_self_block;
    uint64_t fself_mailbox_decrypt_self_block_emulated;
    uint64_t fself_mailbox_decrypt_multiple_self_blocks;
    uint64_t fself_mailbox_decrypt_multiple_self_blocks_emulated;
    uint64_t fself_trap_is_loadable2;
    uint64_t fself_trap_is_loadable2_emulated;
    uint64_t fself_trap_watchpoint;
    uint64_t fself_trap_watchpoint_emulated;
    uint64_t fself_trap_epilogue;
    uint64_t fself_trap_epilogue_emulated;
    uint64_t fself_mailbox_cycles_total;
    uint64_t fself_mailbox_cycles_max;
    uint64_t fself_trap_cycles_total;
    uint64_t fself_trap_cycles_max;

    uint64_t fake_key_has_hits;
    uint64_t fake_key_has_misses;
    uint64_t fake_key_get_hits;
    uint64_t fake_key_get_misses;
    uint64_t fake_key_registers;
    uint64_t fake_key_unregisters;

    uint64_t pfs_derive_calls;
    uint64_t pfs_derive_successes;
    uint64_t pfs_derive_failures;
    uint64_t hmac_cache_hits;
    uint64_t hmac_cache_misses;
    uint64_t xts_cache_hits;
    uint64_t xts_cache_misses;
    uint64_t fpu_enters;
    uint64_t fpu_nested_enters;
    uint64_t fpu_enter_failures;

    uint64_t crypto_requests_total;
    uint64_t crypto_requests_emulated;
    uint64_t crypto_requests_fallback;
    uint64_t crypto_requests_failed;
    uint64_t crypto_requests_restarted;
    uint64_t crypto_messages_total;
    uint64_t crypto_messages_xts;
    uint64_t crypto_messages_hmac;
    uint64_t crypto_messages_other;
    uint64_t crypto_emulated_messages;
    uint64_t hmac_requests;
    uint64_t hmac_bytes;
    uint64_t xts_requests;
    uint64_t xts_sectors;
    uint64_t xts_run_messages_total;
    uint64_t xts_run_coalesced_messages;
    uint64_t xts_run_skip_sectors;

    uint64_t xts_full_direct_runs;
    uint64_t xts_full_direct_sectors;
    uint64_t xts_full_fallback_sectors;

    uint64_t verify_superblock_mailbox;
    uint64_t verify_superblock_emulated;
    uint64_t clear_key_mailbox;
    uint64_t clear_key_emulated;

    uint64_t npdrm_mailbox_total;
    uint64_t npdrm_mailbox_emulated;
    uint64_t npdrm_cmd5;
    uint64_t npdrm_cmd6;
    uint64_t npdrm_debug_rif_matches;
    uint64_t npdrm_reject_bad_lr;
    uint64_t npdrm_reject_copy_in_fail;
    uint64_t npdrm_reject_bad_cmd;
    uint64_t npdrm_reject_bad_rif_type;
    uint64_t npdrm_reject_fpu_fail;
    uint64_t npdrm_reject_bad_hash;
    uint64_t npdrm_reject_bad_secret;
    uint64_t npdrm_reject_copy_out_fail;

    uint64_t virt2phys_calls;
    uint64_t virt2phys_failures;
    uint64_t copy_from_calls;
    uint64_t copy_from_bytes;
    uint64_t copy_from_failures;
    uint64_t copy_to_calls;
    uint64_t copy_to_bytes;
    uint64_t copy_to_failures;

    uint64_t fpkg_reject_xts_non_fake;
    uint64_t fpkg_reject_hmac_non_fake;
    uint64_t fpkg_reject_hmac_bad_shape;
    uint64_t fpkg_reject_other_message;
    uint64_t fpkg_request_no_emulation;
    uint64_t fpkg_request_partial_emulation;
    uint64_t fpkg_request_fpu_enter_fail;

    uint64_t shared_area_snapshots;
    uint64_t log_word_writes;
    uint64_t log_msg_writes;
    uint64_t log_msg_bytes;
};

struct kstuff_word_log_entry
{
    uint64_t seq;
    uint64_t word;
};

struct kstuff_word_log
{
    uint64_t next_seq;
    struct kstuff_word_log_entry entries[SHARED_LOG_WORD_CAP];
};

struct kstuff_ioctl_com_entry
{
    uint64_t com;
    uint32_t total_hits;
    uint32_t emulated_hits;
    uint32_t cmd5_hits;
    uint32_t cmd6_hits;
};

struct kstuff_ioctl_com_table
{
    uint64_t write_lock;
    uint64_t overflows;
    struct kstuff_ioctl_com_entry entries[SHARED_IOCTL_COM_TRACK_CAP];
};

struct kstuff_msg_log
{
    uint64_t write_lock;
    uint64_t next_seq;
    char bytes[SHARED_LOG_MSG_CAP];
};

struct kstuff_snapshot
{
    uint64_t bitmask;
    uint64_t ready_mask;
    struct kstuff_metrics metrics;
    struct kstuff_word_log word_log;
    struct kstuff_ioctl_com_table ioctl_com_table;
    struct kstuff_msg_log msg_log;
};

struct shared_area_layout
{
    uint64_t bitmask;
    uint64_t ready_mask;
    char pad[16];
    uint8_t key_data[SHARED_FAKE_KEY_SLOTS][32];
    struct kstuff_metrics metrics;
    struct kstuff_word_log word_log;
    struct kstuff_ioctl_com_table ioctl_com_table;
    struct kstuff_msg_log msg_log;
};

extern struct shared_area_layout shared_area;

#if KSTUFF_OBS
#define METRIC_INC(field) __atomic_fetch_add(&shared_area.metrics.field, 1, __ATOMIC_RELAXED)
#define METRIC_ADD(field, value) __atomic_fetch_add(&shared_area.metrics.field, (uint64_t)(value), __ATOMIC_RELAXED)
#define METRIC_MAX(field, value) do { \
    uint64_t _metric_max_value = (uint64_t)(value); \
    uint64_t _metric_max_old = __atomic_load_n(&shared_area.metrics.field, __ATOMIC_RELAXED); \
    while(_metric_max_value > _metric_max_old \
       && !__atomic_compare_exchange_n(&shared_area.metrics.field, &_metric_max_old, _metric_max_value, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {} \
} while(0)
#else
#define METRIC_INC(field) do { } while(0)
#define METRIC_ADD(field, value) do { (void)(value); } while(0)
#define METRIC_MAX(field, value) do { (void)(value); } while(0)
#endif

_Static_assert(sizeof(struct kstuff_metrics) == 1520, "unexpected metrics size");
_Static_assert(sizeof(struct kstuff_word_log) == 264, "unexpected word log size");
_Static_assert(sizeof(struct kstuff_ioctl_com_entry) == 24, "unexpected ioctl com entry size");
_Static_assert(sizeof(struct kstuff_ioctl_com_table) == 3088, "unexpected ioctl com table size");
_Static_assert(sizeof(struct kstuff_msg_log) == 504, "unexpected message log size");
_Static_assert(sizeof(struct kstuff_snapshot) == 5392, "unexpected snapshot size");
_Static_assert(sizeof(struct shared_area_layout) == 7424, "unexpected shared_area size");
_Static_assert(sizeof(struct shared_area_layout) <= SHARED_AREA_SIZE, "shared_area must fit in configured mapping");
