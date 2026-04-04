#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "uelf/shared_area.h"

#define KEKCALL_SHARED_AREA_SNAPSHOT 0x600000027
#define KEKCALL_CHECK                0xffffffff00000027

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

static int metrics_equal(const struct kstuff_metrics* a, const struct kstuff_metrics* b)
{
    enum {
        shared_snapshots_off = offsetof(struct kstuff_metrics, shared_area_snapshots),
        after_shared_snapshots_off = offsetof(struct kstuff_metrics, log_word_writes),
    };
    return !memcmp(a, b, shared_snapshots_off)
        && !memcmp((const char*)a + after_shared_snapshots_off,
                   (const char*)b + after_shared_snapshots_off,
                   sizeof(*a) - after_shared_snapshots_off);
}

static int snapshot_shared_area(struct kstuff_snapshot* snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    return (int)kekcall((uint64_t)(uintptr_t)snapshot, sizeof(*snapshot), 0, 0, 0, 0, KEKCALL_SHARED_AREA_SNAPSHOT);
}

static void print_metrics(const struct kstuff_metrics* metrics)
{
#define PRINT_FIELD(name, value) fprintf(stdout, " %s=%" PRIu64, name, (uint64_t)(value))
    fprintf(stdout, "core");
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
    fputc('\n', stdout);

    fprintf(stdout, "decrypt_regs");
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
    fputc('\n', stdout);

    fprintf(stdout, "decrypt_patterns");
    PRINT_FIELD("rsi_only", metrics->debug_reg_decrypt_rsi_only_events);
    PRINT_FIELD("rsi_multi", metrics->debug_reg_decrypt_rsi_multi_events);
    PRINT_FIELD("non_rsi_single", metrics->debug_reg_decrypt_non_rsi_single_events);
    PRINT_FIELD("non_rsi_multi", metrics->debug_reg_decrypt_non_rsi_multi_events);
    fputc('\n', stdout);

    fprintf(stdout, "dispatch");
    PRINT_FIELD("kekcall", metrics->syscall_kekcall_dispatches);
    PRINT_FIELD("fself", metrics->syscall_fself_dispatches);
    PRINT_FIELD("fpkg", metrics->syscall_fpkg_dispatches);
    PRINT_FIELD("ioctl", metrics->syscall_ioctl_dispatches);
    PRINT_FIELD("fix", metrics->syscall_fix_dispatches);
    PRINT_FIELD("fself_traps", metrics->fself_traps);
    PRINT_FIELD("fpkg_traps", metrics->fpkg_traps);
    PRINT_FIELD("fix_traps", metrics->syscall_fix_traps);
    fputc('\n', stdout);

    fprintf(stdout, "fakekeys");
    PRINT_FIELD("has_hit", metrics->fake_key_has_hits);
    PRINT_FIELD("has_miss", metrics->fake_key_has_misses);
    PRINT_FIELD("get_hit", metrics->fake_key_get_hits);
    PRINT_FIELD("get_miss", metrics->fake_key_get_misses);
    PRINT_FIELD("reg", metrics->fake_key_registers);
    PRINT_FIELD("unreg", metrics->fake_key_unregisters);
    PRINT_FIELD("derive", metrics->pfs_derive_calls);
    PRINT_FIELD("derive_ok", metrics->pfs_derive_successes);
    PRINT_FIELD("derive_fail", metrics->pfs_derive_failures);
    fputc('\n', stdout);

    fprintf(stdout, "crypto");
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
    fputc('\n', stdout);

    fprintf(stdout, "xts");
    PRINT_FIELD("req", metrics->xts_requests);
    PRINT_FIELD("sectors", metrics->xts_sectors);
    PRINT_FIELD("run_msg", metrics->xts_run_messages_total);
    PRINT_FIELD("coalesced", metrics->xts_run_coalesced_messages);
    PRINT_FIELD("skipped", metrics->xts_run_skip_sectors);
    PRINT_FIELD("direct_runs", metrics->xts_full_direct_runs);
    PRINT_FIELD("direct_sectors", metrics->xts_full_direct_sectors);
    PRINT_FIELD("fallback", metrics->xts_full_fallback_sectors);
    fputc('\n', stdout);

    fprintf(stdout, "cache_fpu");
    PRINT_FIELD("hmac_hit", metrics->hmac_cache_hits);
    PRINT_FIELD("hmac_miss", metrics->hmac_cache_misses);
    PRINT_FIELD("xts_hit", metrics->xts_cache_hits);
    PRINT_FIELD("xts_miss", metrics->xts_cache_misses);
    PRINT_FIELD("hmac_req", metrics->hmac_requests);
    PRINT_FIELD("hmac_bytes", metrics->hmac_bytes);
    PRINT_FIELD("fpu", metrics->fpu_enters);
    PRINT_FIELD("fpu_nested", metrics->fpu_nested_enters);
    PRINT_FIELD("fpu_fail", metrics->fpu_enter_failures);
    fputc('\n', stdout);

    fprintf(stdout, "fpkg");
    PRINT_FIELD("verify", metrics->verify_superblock_mailbox);
    PRINT_FIELD("verify_emu", metrics->verify_superblock_emulated);
    PRINT_FIELD("clear", metrics->clear_key_mailbox);
    PRINT_FIELD("clear_emu", metrics->clear_key_emulated);
    fputc('\n', stdout);

    fprintf(stdout, "npdrm");
    PRINT_FIELD("total", metrics->npdrm_mailbox_total);
    PRINT_FIELD("emu", metrics->npdrm_mailbox_emulated);
    PRINT_FIELD("cmd5", metrics->npdrm_cmd5);
    PRINT_FIELD("cmd6", metrics->npdrm_cmd6);
    PRINT_FIELD("debug_rif", metrics->npdrm_debug_rif_matches);
    fputc('\n', stdout);

    fprintf(stdout, "copy");
    PRINT_FIELD("v2p", metrics->virt2phys_calls);
    PRINT_FIELD("v2p_fail", metrics->virt2phys_failures);
    PRINT_FIELD("in", metrics->copy_from_calls);
    PRINT_FIELD("in_bytes", metrics->copy_from_bytes);
    PRINT_FIELD("in_fail", metrics->copy_from_failures);
    PRINT_FIELD("out", metrics->copy_to_calls);
    PRINT_FIELD("out_bytes", metrics->copy_to_bytes);
    PRINT_FIELD("out_fail", metrics->copy_to_failures);
    fputc('\n', stdout);

    fprintf(stdout, "obs");
    PRINT_FIELD("snapshots", metrics->shared_area_snapshots);
    PRINT_FIELD("log_word", metrics->log_word_writes);
    PRINT_FIELD("log_msg", metrics->log_msg_writes);
    PRINT_FIELD("log_bytes", metrics->log_msg_bytes);
    fputc('\n', stdout);
    fflush(stdout);
#undef PRINT_FIELD
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
        fprintf(stdout, "log-word[%" PRIu64 "]=0x%016" PRIx64 "\n", seq, entry->word);
    }

    *last_seq = cur;
    fflush(stdout);
}

static void print_new_msg_log(const struct kstuff_snapshot* snapshot, uint64_t* last_seq)
{
    uint64_t cur = snapshot->msg_log.next_seq;
    uint64_t start = *last_seq;

    if(cur - start > SHARED_LOG_MSG_CAP)
        start = cur - SHARED_LOG_MSG_CAP;
    if(start == cur)
        return;

    fputs("log-msg: ", stdout);
    while(start < cur)
    {
        size_t off = start % SHARED_LOG_MSG_CAP;
        size_t chunk = SHARED_LOG_MSG_CAP - off;
        if(chunk > cur - start)
            chunk = (size_t)(cur - start);
        fwrite(snapshot->msg_log.bytes + off, 1, chunk, stdout);
        start += chunk;
    }

    if(snapshot->msg_log.bytes[(cur - 1) % SHARED_LOG_MSG_CAP] != '\n')
        fputc('\n', stdout);

    *last_seq = cur;
    fflush(stdout);
}

int main(void)
{
    struct kstuff_snapshot snapshot;
    struct kstuff_metrics last_metrics;
    uint64_t last_word_seq = 0;
    uint64_t last_msg_seq = 0;
    int have_last_metrics = 0;
    const struct timespec delay = {1, 0};

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    fprintf(stderr, "debug-reader: start\n");

    if(kekcall(0, 0, 0, 0, 0, 0, KEKCALL_CHECK))
    {
        fprintf(stderr, "debug-reader: ps5-kstuff is not loaded\n");
        return 1;
    }

    fprintf(stderr, "debug-reader: attached\n");

    for(;;)
    {
        int err = snapshot_shared_area(&snapshot);
        if(err)
        {
            fprintf(stderr, "debug-reader: shared_area snapshot failed: %d\n", err);
            return 1;
        }

        print_new_msg_log(&snapshot, &last_msg_seq);
        print_new_word_log(&snapshot, &last_word_seq);
        if(!have_last_metrics || !metrics_equal(&last_metrics, &snapshot.metrics))
        {
            print_metrics(&snapshot.metrics);
            last_metrics = snapshot.metrics;
            have_last_metrics = 1;
        }

        nanosleep(&delay, NULL);
    }
}
