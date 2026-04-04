#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include "../freebsd-headers/sys/ioccom.h"
#include "uelf/shared_area.h"
#include "uelf/fself.h"
#include "uelf/syscall_fixes.h"

#define KEKCALL_SHARED_AREA_SNAPSHOT 0x600000027
#define KEKCALL_CHECK                0xffffffff00000027

static FILE* g_log_file;
static char g_stdout_buf[8192];
static char g_log_file_buf[16384];

static int64_t kekcall(uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f, uint64_t g)
{
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    uint64_t ret;
    unsigned char is_error;

    __asm__ __volatile__(
        "syscall"
        : "=a"(ret), "=@ccc"(is_error), "+r"(r10), "+r"(r8), "+r"(r9)
        : "a"(g), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory");

    return is_error ? -(int64_t)ret : (int64_t)ret;
}

static void tee_vfprintf(FILE* stream, const char* fmt, va_list ap)
{
    va_list ap_copy;

    va_copy(ap_copy, ap);
    vfprintf(stream, fmt, ap);
    if(g_log_file)
        vfprintf(g_log_file, fmt, ap_copy);
    va_end(ap_copy);
}

static void tee_printf(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    tee_vfprintf(stdout, fmt, ap);
    va_end(ap);
}

static void tee_errprintf(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    tee_vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void tee_putc(int ch)
{
    fputc(ch, stdout);
    if(g_log_file)
        fputc(ch, g_log_file);
}

static void tee_write(const void* ptr, size_t size)
{
    fwrite(ptr, 1, size, stdout);
    if(g_log_file)
        fwrite(ptr, 1, size, g_log_file);
}

static void tee_flush(void)
{
    fflush(stdout);
    if(g_log_file)
        fflush(g_log_file);
}

static void tee_print_percent(uint64_t part, uint64_t total)
{
    uint64_t milli_pct = 0;

    if(total)
        milli_pct = (part * 100000 + (total / 2)) / total;

    tee_printf("%" PRIu64 ".%03" PRIu64 "%%", milli_pct / 1000, milli_pct % 1000);
}

static int snapshot_shared_area(struct kstuff_snapshot* snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    return (int)kekcall((uint64_t)(uintptr_t)snapshot, sizeof(*snapshot), 0, 0, 0, 0, KEKCALL_SHARED_AREA_SNAPSHOT);
}

static void reopen_log_file(void)
{
    if(g_log_file)
    {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    g_log_file = fopen("/data/kstuff_debug.log", "w");
    if(g_log_file)
        setvbuf(g_log_file, g_log_file_buf, _IOFBF, sizeof(g_log_file_buf));
}

static void print_metrics(const struct kstuff_metrics* metrics)
{
#define PRINT_FIELD(name, value) tee_printf(" %s=%" PRIu64, name, (uint64_t)(value))
    tee_printf("core");
    PRINT_FIELD("handle", metrics->handle_entries);
    PRINT_FIELD("from_user", metrics->handle_from_userspace_entries);
    PRINT_FIELD("doreti", metrics->handle_doreti_iret_entries);
    PRINT_FIELD("decrypt_fixups", metrics->debug_reg_decrypt_events);
    PRINT_FIELD("debug_unhandled", metrics->debug_unhandled_traps);
    PRINT_FIELD("mailbox", metrics->mailbox_traps);
    PRINT_FIELD("mailbox_fself", metrics->mailbox_fself);
    PRINT_FIELD("mailbox_fpkg", metrics->mailbox_fpkg);
    PRINT_FIELD("mailbox_npdrm", metrics->mailbox_npdrm);
    PRINT_FIELD("mailbox_unhandled", metrics->mailbox_unhandled);
    tee_putc('\n');

    tee_printf("decrypt_regs");
    PRINT_FIELD("rax", metrics->debug_reg_decrypt_rax);
    PRINT_FIELD("rcx", metrics->debug_reg_decrypt_rcx);
    PRINT_FIELD("rdx", metrics->debug_reg_decrypt_rdx);
    PRINT_FIELD("rbx", metrics->debug_reg_decrypt_rbx);
    PRINT_FIELD("rbp", metrics->debug_reg_decrypt_rbp);
    PRINT_FIELD("rsi", metrics->debug_reg_decrypt_rsi);
    PRINT_FIELD("rdi", metrics->debug_reg_decrypt_rdi);
    PRINT_FIELD("r8", metrics->debug_reg_decrypt_r8);
    PRINT_FIELD("r9", metrics->debug_reg_decrypt_r9);
    PRINT_FIELD("r10", metrics->debug_reg_decrypt_r10);
    PRINT_FIELD("r11", metrics->debug_reg_decrypt_r11);
    PRINT_FIELD("r12", metrics->debug_reg_decrypt_r12);
    PRINT_FIELD("r13", metrics->debug_reg_decrypt_r13);
    PRINT_FIELD("r14", metrics->debug_reg_decrypt_r14);
    PRINT_FIELD("r15", metrics->debug_reg_decrypt_r15);
    tee_putc('\n');

    tee_printf("decrypt_patterns");
    PRINT_FIELD("rsi_only", metrics->debug_reg_decrypt_rsi_only_events);
    PRINT_FIELD("rsi_multi", metrics->debug_reg_decrypt_rsi_multi_events);
    PRINT_FIELD("non_rsi_single", metrics->debug_reg_decrypt_non_rsi_single_events);
    PRINT_FIELD("non_rsi_multi", metrics->debug_reg_decrypt_non_rsi_multi_events);
    tee_putc('\n');

    tee_printf("dispatch");
    PRINT_FIELD("kekcall", metrics->syscall_kekcall_dispatches);
    PRINT_FIELD("fself", metrics->syscall_fself_dispatches);
    PRINT_FIELD("fpkg", metrics->syscall_fpkg_dispatches);
    PRINT_FIELD("ioctl", metrics->syscall_ioctl_dispatches);
    PRINT_FIELD("fix", metrics->syscall_fix_dispatches);
    PRINT_FIELD("fself_traps", metrics->fself_traps);
    PRINT_FIELD("fpkg_traps", metrics->fpkg_traps);
    PRINT_FIELD("fix_traps", metrics->syscall_fix_traps);
    tee_putc('\n');

    tee_printf("ioctl_prefilter");
    PRINT_FIELD("allowed", metrics->ioctl_prefilter_allowed);
    PRINT_FIELD("skipped", metrics->ioctl_prefilter_skipped);
    PRINT_FIELD("copy_fail_open", metrics->ioctl_prefilter_copy_in_fail_open);
    tee_putc('\n');

    tee_printf("cycles");
    PRINT_FIELD("handle_total", metrics->handle_cycles_total);
    PRINT_FIELD("handle_max", metrics->handle_cycles_max);
    PRINT_FIELD("syscall_total", metrics->handle_syscall_cycles_total);
    PRINT_FIELD("syscall_max", metrics->handle_syscall_cycles_max);
    PRINT_FIELD("decrypt_total", metrics->generic_decrypt_cycles_total);
    PRINT_FIELD("decrypt_max", metrics->generic_decrypt_cycles_max);
    PRINT_FIELD("fself_mb_total", metrics->fself_mailbox_cycles_total);
    PRINT_FIELD("fself_mb_max", metrics->fself_mailbox_cycles_max);
    PRINT_FIELD("fself_trap_total", metrics->fself_trap_cycles_total);
    PRINT_FIELD("fself_trap_max", metrics->fself_trap_cycles_max);
    PRINT_FIELD("fpkg_total", metrics->fpkg_crypto_request_cycles_total);
    PRINT_FIELD("fpkg_max", metrics->fpkg_crypto_request_cycles_max);
    PRINT_FIELD("npdrm_total", metrics->npdrm_mailbox_cycles_total);
    PRINT_FIELD("npdrm_max", metrics->npdrm_mailbox_cycles_max);
    PRINT_FIELD("xts_total", metrics->xts_cycles_total);
    PRINT_FIELD("xts_max", metrics->xts_cycles_max);
    PRINT_FIELD("v2p_total", metrics->virt2phys_cycles_total);
    PRINT_FIELD("v2p_max", metrics->virt2phys_cycles_max);
    PRINT_FIELD("in_total", metrics->copy_from_cycles_total);
    PRINT_FIELD("in_max", metrics->copy_from_cycles_max);
    PRINT_FIELD("out_total", metrics->copy_to_cycles_total);
    PRINT_FIELD("out_max", metrics->copy_to_cycles_max);
    tee_putc('\n');

    tee_printf("fself_cache");
    PRINT_FIELD("hdr_hit", metrics->fself_header_cache_hits);
    PRINT_FIELD("hdr_miss", metrics->fself_header_cache_misses);
    PRINT_FIELD("ctx_hit", metrics->fself_context_cache_hits);
    PRINT_FIELD("ctx_miss", metrics->fself_context_cache_misses);
    PRINT_FIELD("parse_ok", metrics->fself_header_parse_fself);
    PRINT_FIELD("parse_not", metrics->fself_header_parse_not_fself);
    PRINT_FIELD("parse_fail", metrics->fself_header_parse_failures);
    PRINT_FIELD("auth_load", metrics->fself_authinfo_loads);
    PRINT_FIELD("auth_found", metrics->fself_authinfo_found);
    tee_putc('\n');

    tee_printf("fself_mailbox");
    PRINT_FIELD("verify", metrics->fself_mailbox_verify_header);
    PRINT_FIELD("verify_emu", metrics->fself_mailbox_verify_header_emulated);
    PRINT_FIELD("load_seg", metrics->fself_mailbox_load_self_segment);
    PRINT_FIELD("load_seg_emu", metrics->fself_mailbox_load_self_segment_emulated);
    PRINT_FIELD("dec1", metrics->fself_mailbox_decrypt_self_block);
    PRINT_FIELD("dec1_emu", metrics->fself_mailbox_decrypt_self_block_emulated);
    PRINT_FIELD("decn", metrics->fself_mailbox_decrypt_multiple_self_blocks);
    PRINT_FIELD("decn_emu", metrics->fself_mailbox_decrypt_multiple_self_blocks_emulated);
    tee_putc('\n');

    tee_printf("fself_trap");
    PRINT_FIELD("loadable2", metrics->fself_trap_is_loadable2);
    PRINT_FIELD("loadable2_emu", metrics->fself_trap_is_loadable2_emulated);
    PRINT_FIELD("watch", metrics->fself_trap_watchpoint);
    PRINT_FIELD("watch_emu", metrics->fself_trap_watchpoint_emulated);
    PRINT_FIELD("epilogue", metrics->fself_trap_epilogue);
    PRINT_FIELD("epilogue_emu", metrics->fself_trap_epilogue_emulated);
    tee_putc('\n');

    tee_printf("fakekeys");
    PRINT_FIELD("has_hit", metrics->fake_key_has_hits);
    PRINT_FIELD("has_miss", metrics->fake_key_has_misses);
    PRINT_FIELD("get_hit", metrics->fake_key_get_hits);
    PRINT_FIELD("get_miss", metrics->fake_key_get_misses);
    PRINT_FIELD("reg", metrics->fake_key_registers);
    PRINT_FIELD("unreg", metrics->fake_key_unregisters);
    PRINT_FIELD("derive", metrics->pfs_derive_calls);
    PRINT_FIELD("derive_ok", metrics->pfs_derive_successes);
    PRINT_FIELD("derive_fail", metrics->pfs_derive_failures);
    tee_putc('\n');

    tee_printf("crypto");
    PRINT_FIELD("req", metrics->crypto_requests_total);
    PRINT_FIELD("emu", metrics->crypto_requests_emulated);
    PRINT_FIELD("fallback", metrics->crypto_requests_fallback);
    PRINT_FIELD("fail", metrics->crypto_requests_failed);
    PRINT_FIELD("restart", metrics->crypto_requests_restarted);
    PRINT_FIELD("msg", metrics->crypto_messages_total);
    PRINT_FIELD("xts_msg", metrics->crypto_messages_xts);
    PRINT_FIELD("hmac_msg", metrics->crypto_messages_hmac);
    PRINT_FIELD("other_msg", metrics->crypto_messages_other);
    PRINT_FIELD("emu_msg", metrics->crypto_emulated_messages);
    tee_putc('\n');

    tee_printf("xts");
    PRINT_FIELD("req", metrics->xts_requests);
    PRINT_FIELD("sectors", metrics->xts_sectors);
    PRINT_FIELD("run_msg", metrics->xts_run_messages_total);
    PRINT_FIELD("coalesced", metrics->xts_run_coalesced_messages);
    PRINT_FIELD("skipped", metrics->xts_run_skip_sectors);
    PRINT_FIELD("direct_runs", metrics->xts_full_direct_runs);
    PRINT_FIELD("direct_sectors", metrics->xts_full_direct_sectors);
    PRINT_FIELD("fallback", metrics->xts_full_fallback_sectors);
    tee_putc('\n');

    tee_printf("cache_fpu");
    PRINT_FIELD("hmac_hit", metrics->hmac_cache_hits);
    PRINT_FIELD("hmac_miss", metrics->hmac_cache_misses);
    PRINT_FIELD("xts_hit", metrics->xts_cache_hits);
    PRINT_FIELD("xts_miss", metrics->xts_cache_misses);
    PRINT_FIELD("hmac_req", metrics->hmac_requests);
    PRINT_FIELD("hmac_bytes", metrics->hmac_bytes);
    PRINT_FIELD("fpu", metrics->fpu_enters);
    PRINT_FIELD("fpu_nested", metrics->fpu_nested_enters);
    PRINT_FIELD("fpu_fail", metrics->fpu_enter_failures);
    tee_putc('\n');

    tee_printf("fpkg");
    PRINT_FIELD("verify", metrics->verify_superblock_mailbox);
    PRINT_FIELD("verify_emu", metrics->verify_superblock_emulated);
    PRINT_FIELD("clear", metrics->clear_key_mailbox);
    PRINT_FIELD("clear_emu", metrics->clear_key_emulated);
    tee_putc('\n');

    tee_printf("fpkg_rejects");
    PRINT_FIELD("xts_non_fake", metrics->fpkg_reject_xts_non_fake);
    PRINT_FIELD("hmac_non_fake", metrics->fpkg_reject_hmac_non_fake);
    PRINT_FIELD("hmac_shape", metrics->fpkg_reject_hmac_bad_shape);
    PRINT_FIELD("other", metrics->fpkg_reject_other_message);
    PRINT_FIELD("no_emu", metrics->fpkg_request_no_emulation);
    PRINT_FIELD("partial", metrics->fpkg_request_partial_emulation);
    PRINT_FIELD("fpu_fail", metrics->fpkg_request_fpu_enter_fail);
    tee_putc('\n');

    tee_printf("npdrm");
    PRINT_FIELD("total", metrics->npdrm_mailbox_total);
    PRINT_FIELD("emu", metrics->npdrm_mailbox_emulated);
    PRINT_FIELD("cmd5", metrics->npdrm_cmd5);
    PRINT_FIELD("cmd6", metrics->npdrm_cmd6);
    PRINT_FIELD("debug_rif", metrics->npdrm_debug_rif_matches);
    tee_putc('\n');

    tee_printf("npdrm_rejects");
    PRINT_FIELD("bad_lr", metrics->npdrm_reject_bad_lr);
    PRINT_FIELD("copy_in", metrics->npdrm_reject_copy_in_fail);
    PRINT_FIELD("bad_cmd", metrics->npdrm_reject_bad_cmd);
    PRINT_FIELD("bad_type", metrics->npdrm_reject_bad_rif_type);
    PRINT_FIELD("fpu_fail", metrics->npdrm_reject_fpu_fail);
    PRINT_FIELD("bad_hash", metrics->npdrm_reject_bad_hash);
    PRINT_FIELD("bad_secret", metrics->npdrm_reject_bad_secret);
    PRINT_FIELD("copy_out", metrics->npdrm_reject_copy_out_fail);
    tee_putc('\n');

    tee_printf("copy");
    PRINT_FIELD("v2p", metrics->virt2phys_calls);
    PRINT_FIELD("v2p_fail", metrics->virt2phys_failures);
    PRINT_FIELD("in", metrics->copy_from_calls);
    PRINT_FIELD("in_bytes", metrics->copy_from_bytes);
    PRINT_FIELD("in_fail", metrics->copy_from_failures);
    PRINT_FIELD("out", metrics->copy_to_calls);
    PRINT_FIELD("out_bytes", metrics->copy_to_bytes);
    PRINT_FIELD("out_fail", metrics->copy_to_failures);
    tee_putc('\n');

    tee_printf("obs");
    PRINT_FIELD("snapshots", metrics->shared_area_snapshots);
    PRINT_FIELD("log_word", metrics->log_word_writes);
    PRINT_FIELD("log_msg", metrics->log_msg_writes);
    PRINT_FIELD("log_bytes", metrics->log_msg_bytes);
    tee_putc('\n');
#undef PRINT_FIELD
}

static const char* ioctl_dir_name(uint64_t com)
{
    switch(com & IOC_DIRMASK)
    {
        case IOC_VOID: return "VOID";
        case IOC_OUT: return "OUT";
        case IOC_IN: return "IN";
        case IOC_INOUT: return "INOUT";
        default: return "UNKNOWN";
    }
}

static void print_ioctl_com_table(const struct kstuff_ioctl_com_table* table, uint64_t total_ioctl)
{
    int printed = 0;
    tee_printf("ioctl-com-meta cap=%u overflows=%" PRIu64 " total=%" PRIu64 "\n",
               (unsigned)SHARED_IOCTL_COM_TRACK_CAP,
               table->overflows,
               total_ioctl);
    printed = 1;
    for(size_t i = 0; i < SHARED_IOCTL_COM_TRACK_CAP; i++)
    {
        const struct kstuff_ioctl_com_entry* entry = &table->entries[i];
        if(!entry->emulated_hits)
            continue;
        tee_printf("ioctl-com[%zu] syscall_id=%u com=0x%016" PRIx64
                   " dir=%s len=%u group=0x%02x num=0x%02x total=%" PRIu64
                   " emu=%" PRIu64 " cmd5=%" PRIu64 " cmd6=%" PRIu64 " pct=",
                   i,
                   (unsigned)SYS_ioctl,
                   entry->com,
                   ioctl_dir_name(entry->com),
                   (unsigned)IOCPARM_LEN(entry->com),
                   (unsigned)IOCGROUP(entry->com),
                   (unsigned)(entry->com & 0xff),
                   (uint64_t)entry->total_hits,
                   (uint64_t)entry->emulated_hits,
                   (uint64_t)entry->cmd5_hits,
                   (uint64_t)entry->cmd6_hits);
        tee_print_percent(entry->emulated_hits, total_ioctl);
        tee_printf(" conv=");
        tee_print_percent(entry->emulated_hits, entry->total_hits);
        tee_putc('\n');
        printed = 1;
    }
    (void)printed;
}

static void print_syscall_stats(const struct kstuff_metrics* metrics)
{
    struct row
    {
        const char* name;
        unsigned id;
        uint64_t armed;
        uint64_t trap;
        uint64_t emu;
    } rows[] = {
        {"execve", SYS_execve, metrics->syscall_execve_armed, metrics->syscall_execve_trap, metrics->syscall_execve_emulated},
        {"dynlib_load_prx", SYS_dynlib_load_prx, metrics->syscall_dynlib_load_prx_armed, metrics->syscall_dynlib_load_prx_trap, metrics->syscall_dynlib_load_prx_emulated},
        {"get_self_auth_info", SYS_get_self_auth_info, metrics->syscall_get_self_auth_info_armed, metrics->syscall_get_self_auth_info_trap, metrics->syscall_get_self_auth_info_emulated},
        {"get_sdk_compiled_version", SYS_get_sdk_compiled_version, metrics->syscall_get_sdk_compiled_version_armed, metrics->syscall_get_sdk_compiled_version_trap, metrics->syscall_get_sdk_compiled_version_emulated},
        {"get_ppr_sdk_compiled_version", SYS_get_ppr_sdk_compiled_version, metrics->syscall_get_ppr_sdk_compiled_version_armed, metrics->syscall_get_ppr_sdk_compiled_version_trap, metrics->syscall_get_ppr_sdk_compiled_version_emulated},
        {"mmap", SYS_mmap, metrics->syscall_mmap_armed, metrics->syscall_mmap_trap, metrics->syscall_mmap_emulated},
        {"mlock", SYS_mlock, metrics->syscall_mlock_armed, metrics->syscall_mlock_trap, metrics->syscall_mlock_emulated},
        {"nmount", SYS_nmount, metrics->syscall_nmount_armed, metrics->syscall_nmount_trap, metrics->syscall_nmount_emulated},
        {"unmount", SYS_unmount, metrics->syscall_unmount_armed, metrics->syscall_unmount_trap, metrics->syscall_unmount_emulated},
        {"ioctl", SYS_ioctl, metrics->syscall_ioctl_armed, metrics->syscall_ioctl_trap, metrics->syscall_ioctl_emulated},
        {"mprotect", SYS_mprotect, metrics->syscall_mprotect_armed, metrics->syscall_mprotect_trap, metrics->syscall_mprotect_emulated},
        {"mdbg_call", SYS_mdbg_call, metrics->syscall_mdbg_call_armed, metrics->syscall_mdbg_call_trap, metrics->syscall_mdbg_call_emulated},
    };
    int printed = 0;

    for(size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    {
        if(!(rows[i].armed || rows[i].trap || rows[i].emu))
            continue;
        tee_printf("syscall[%s] id=%u armed=%" PRIu64 " trap=%" PRIu64 " emu=%" PRIu64 "\n",
                   rows[i].name, rows[i].id, rows[i].armed, rows[i].trap, rows[i].emu);
        printed = 1;
    }
    (void)printed;
}

static void print_new_word_log(const struct kstuff_snapshot* snapshot, uint64_t* last_seq)
{
    uint64_t cur = snapshot->word_log.next_seq;
    uint64_t start = *last_seq;

    if(cur - start > SHARED_LOG_WORD_CAP)
        start = cur - SHARED_LOG_WORD_CAP;

    for(uint64_t seq = start; seq < cur; seq++)
    {
        const struct kstuff_word_log_entry* entry = &snapshot->word_log.entries[seq % SHARED_LOG_WORD_CAP];
        if(entry->seq != seq + 1)
            continue;
        tee_printf("log-word[%" PRIu64 "]=0x%016" PRIx64 "\n", seq, entry->word);
    }

    *last_seq = cur;
}

static void print_new_msg_log(const struct kstuff_snapshot* snapshot, uint64_t* last_seq)
{
    uint64_t cur = snapshot->msg_log.next_seq;
    uint64_t start = *last_seq;

    if(cur - start > SHARED_LOG_MSG_CAP)
        start = cur - SHARED_LOG_MSG_CAP;
    if(start == cur)
        return;

    tee_printf("log-msg: ");
    while(start < cur)
    {
        size_t off = start % SHARED_LOG_MSG_CAP;
        size_t chunk = SHARED_LOG_MSG_CAP - off;
        if(chunk > cur - start)
            chunk = (size_t)(cur - start);
        tee_write(snapshot->msg_log.bytes + off, chunk);
        start += chunk;
    }

    if(snapshot->msg_log.bytes[(cur - 1) % SHARED_LOG_MSG_CAP] != '\n')
        tee_putc('\n');

    *last_seq = cur;
}

int main(void)
{
    struct kstuff_snapshot snapshot;
    const struct timespec delay = {10, 0};

    setvbuf(stdout, g_stdout_buf, _IOLBF, sizeof(g_stdout_buf));
    setvbuf(stderr, NULL, _IONBF, 0);
    reopen_log_file();

    tee_errprintf("debug-reader: start\n");
    tee_flush();
    if(!g_log_file)
    {
        tee_errprintf("debug-reader: failed to open /data/kstuff_debug.log\n");
        tee_flush();
    }

    if(kekcall(0, 0, 0, 0, 0, 0, KEKCALL_CHECK))
    {
        tee_errprintf("debug-reader: ps5-kstuff is not loaded\n");
        tee_flush();
        return 1;
    }

    tee_errprintf("debug-reader: attached\n");
    tee_flush();

    for(;;)
    {
        uint64_t word_seq = 0;
        uint64_t msg_seq = 0;
        int err = snapshot_shared_area(&snapshot);
        if(err)
        {
            tee_errprintf("debug-reader: shared_area snapshot failed: %d\n", err);
            tee_flush();
            return 1;
        }

        reopen_log_file();
        if(!g_log_file)
            tee_errprintf("debug-reader: failed to open /data/kstuff_debug.log\n");

        print_new_msg_log(&snapshot, &msg_seq);
        print_new_word_log(&snapshot, &word_seq);
        print_metrics(&snapshot.metrics);
        print_syscall_stats(&snapshot.metrics);
        print_ioctl_com_table(&snapshot.ioctl_com_table, snapshot.metrics.syscall_ioctl_dispatches);

        tee_flush();

        nanosleep(&delay, NULL);
    }
}
