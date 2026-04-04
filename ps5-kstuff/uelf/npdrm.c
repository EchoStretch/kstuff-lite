// https://github.com/PS5Dev/Byepervisor/blob/57204cbd7bd26ed4623634d52b0f60f40d630087/hen/src/fpkg.cpp#L82

#include <string.h>
#include <sys/ioccom.h>
#include <sys/sysproto.h>
#include "utils.h"
#include "npdrm.h"
#include "log.h"
#include "fpu.h"
#include "sha256.h"

#include <isa-l_crypto/aes_cbc.h>
#include <isa-l_crypto/aes_keyexp.h>

// #define NPDRM_PORTING 1

#ifndef NPDRM_PORTING
extern char sceSblServiceMailbox_lr_npdrm_cmd_5[];
extern char sceSblServiceMailbox_lr_npdrm_cmd_6[];
#endif
extern char sceSblServiceMailbox[];

static const uint8_t rif_debug_key[] = {0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12};

enum { AES128_EXPKEY_SIZE = 16 * 11 };
enum {
    NPDRM_EXPECT_CMD5 = 1u << 0,
    NPDRM_EXPECT_CMD6 = 1u << 1,
};

static struct
{
#if KSTUFF_OBS
    uint64_t com;
#endif
    uint8_t expected_cmd_mask;
    uint8_t valid;
} s_current_ioctl_state;

void finish_npdrm_ioctl_state(void)
{
    s_current_ioctl_state.expected_cmd_mask = 0;
    s_current_ioctl_state.valid = 0;
}

static struct
{
    uint8_t enc_exp_key[AES128_EXPKEY_SIZE] __attribute__((aligned(16)));
    uint8_t dec_exp_key[AES128_EXPKEY_SIZE] __attribute__((aligned(16)));
    int valid;
} s_rif_debug_key_schedule;

static int aes_cbc_128_decrypt_rif_debug_fpu_held(uint8_t *out, const uint8_t *in, int size, const uint8_t *iv)
{
    int err = -1;
    if (!s_rif_debug_key_schedule.valid)
    {
        if (isal_aes_keyexp_128(rif_debug_key, s_rif_debug_key_schedule.enc_exp_key,
                                s_rif_debug_key_schedule.dec_exp_key))
            goto exit;
        s_rif_debug_key_schedule.valid = 1;
    }
    if (isal_aes_cbc_dec_128(in, iv, s_rif_debug_key_schedule.dec_exp_key, out, size))
        goto exit;
    err = 0;
exit:
    return err;
}

static int sha256_buffer_fpu_held(const unsigned char *in, unsigned long inlen, unsigned char *out)
{
    struct uelf_sha256_context ctx;
    int err = -1;

    uelf_sha256_init(&ctx);
    if(uelf_sha256_update(&ctx, in, inlen))
        goto exit;
    if(uelf_sha256_final(&ctx, out))
        goto exit;
    err = 0;
exit:
    return err;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    for (size_t i = 0; i < n; i++)
    {
        if (p1[i] != p2[i])
        {
            return (int)p1[i] - (int)p2[i];
        }
    }
    return 0;
}

int try_handle_npdrm_mailbox(uint64_t *regs, uint64_t lr)
{
    METRIC_TIME_START(start_cycles);
#define RETURN_NPDRM(value) do { METRIC_TIME(npdrm_mailbox_cycles_total, npdrm_mailbox_cycles_max, start_cycles); return (value); } while(0)
    struct {
        uint32_t cmd;
        uint32_t _pad;
        uint64_t rif_pa;
    } request_hdr;
    uint32_t cmd;
#ifndef NPDRM_PORTING
    if (lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_5 &&
        lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_6)
    {
        METRIC_INC(npdrm_reject_bad_lr);
        RETURN_NPDRM(0);
    }
    cmd = (lr == (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_5) ? 5u : 6u;
    if (s_current_ioctl_state.valid)
    {
        const uint8_t lr_cmd_mask = (cmd == 5u) ? NPDRM_EXPECT_CMD5 : NPDRM_EXPECT_CMD6;
        if (!(s_current_ioctl_state.expected_cmd_mask & lr_cmd_mask))
        {
            METRIC_INC(npdrm_reject_bad_cmd);
            RETURN_NPDRM(1);
        }
    }
    if (copy_from_kernel(&request_hdr, regs[RDX], sizeof(request_hdr)))
    {
        METRIC_INC(npdrm_reject_copy_in_fail);
        RETURN_NPDRM(1);
    }
    if (request_hdr.cmd != cmd)
    {
        METRIC_INC(npdrm_reject_bad_cmd);
        RETURN_NPDRM(1);
    }
#else
    if (copy_from_kernel(&request_hdr, regs[RDX], sizeof(request_hdr)))
    {
        METRIC_INC(npdrm_reject_copy_in_fail);
        RETURN_NPDRM(0);
    }
    // Other functions may use this same cmd number for different purposes (depending on RDI/handle i believe, however its value changes between fws)
    // for example, sceSblServiceMailbox_lr_decryptSelfBlock also sees cmd 6
    // if we only relied on this, it would work safely because of the later checks, its just wasteful
    if (request_hdr.cmd != 5 && request_hdr.cmd != 6)
    {
        METRIC_INC(npdrm_reject_bad_cmd);
        RETURN_NPDRM(0);
    }
    cmd = request_hdr.cmd;
#endif
    METRIC_INC(npdrm_mailbox_total);
    if(cmd == 5)
        METRIC_INC(npdrm_cmd5);
    else if(cmd == 6)
        METRIC_INC(npdrm_cmd6);

    uint64_t rif_pa = request_hdr.rif_pa;
    const struct Rif* rif = (const struct Rif*)(DMEM + rif_pa);

    if (rif->type != 0x2)
    {
        METRIC_INC(npdrm_reject_bad_rif_type);
#ifdef NPDRM_PORTING
        RETURN_NPDRM(0);
#else
        RETURN_NPDRM(1);
#endif
    }

    if (uelf_fpu_enter())
    {
        METRIC_INC(npdrm_reject_fpu_fail);
#ifdef NPDRM_PORTING
        RETURN_NPDRM(0);
#else
        RETURN_NPDRM(1);
#endif
    }
    uint8_t contentid_hash[32];
    if (sha256_buffer_fpu_held(rif->contentId, sizeof(rif->contentId), contentid_hash))
    {
        uelf_fpu_exit();
        METRIC_INC(npdrm_reject_bad_hash);
#ifdef NPDRM_PORTING
        RETURN_NPDRM(0);
#else
        RETURN_NPDRM(1);
#endif
    }

    if (memcmp(contentid_hash, rif->rifIv, 16) != 0)
    {
        uelf_fpu_exit();
        METRIC_INC(npdrm_reject_bad_hash);
#ifdef NPDRM_PORTING
        RETURN_NPDRM(0);
#else
        // not a debug rif
        RETURN_NPDRM(1);
#endif
    }
    METRIC_INC(npdrm_debug_rif_matches);

#ifdef NPDRM_PORTING
    // Now that we know the input data is a (debug) rif, we know we are at the right place
    log_word(0x10C7100000000001UL + ((uint64_t)cmd << 16));
    log_word(lr);
#endif

#ifdef NPDRM_PORTING
    if (cmd == 6)
#else
    if (cmd == 6)
#endif
    {
        uint8_t decrypted_secret[sizeof(rif->rifSecret)];
        if (aes_cbc_128_decrypt_rif_debug_fpu_held(decrypted_secret, rif->rifSecret,
                                                   sizeof(rif->rifSecret), rif->rifIv))
        {
            uelf_fpu_exit();
            METRIC_INC(npdrm_reject_bad_secret);
            RETURN_NPDRM(1);
        }

        if (memcmp(contentid_hash + 16, decrypted_secret, 16) != 0)
        {
            uelf_fpu_exit();
            // does not use debug rif key/failed to decrypt?
            METRIC_INC(npdrm_reject_bad_secret);
            RETURN_NPDRM(1);
        }

        // copy both unk10 and unk20
        if(copy_to_kernel(regs[RDX] + __builtin_offsetof(struct NpDrmCmd6, unk10), &decrypted_secret[0x70], 0x20))
        {
            uelf_fpu_exit();
            METRIC_INC(npdrm_reject_copy_out_fail);
            RETURN_NPDRM(1);
        }
    }

    struct RifOutput output;
    output.version = __builtin_bswap16(rif->version);
    output.unk04 = __builtin_bswap16(rif->unk06);
    output.psnid = __builtin_bswap64(rif->psnid);
    output.startTimestamp = __builtin_bswap64(rif->startTimestamp);
    output.endTimestamp = __builtin_bswap64(rif->endTimestamp);
    output.extraFlags = __builtin_bswap64(rif->extraFlags);
    output.type = __builtin_bswap16(rif->type);
    output.contentType = __builtin_bswap16(rif->contentType);
    output.skuFlag = __builtin_bswap16(rif->skuFlag);
    output.unk34 = __builtin_bswap32(rif->unk60);
    output.unk38 = __builtin_bswap32(rif->unk64);
    output.unk3C = 0;
    output.unk40 = 0;
    output.unk44 = 0;
    memcpy(output.contentId, rif->contentId, sizeof(output.contentId));
    memcpy(output.rifIv, rif->rifIv, sizeof(output.rifIv));
    output.unk88 = __builtin_bswap32(rif->unk70);
    output.unk8C = __builtin_bswap32(rif->unk74);
    output.unk90 = __builtin_bswap32(rif->unk78);
    output.unk94 = __builtin_bswap32(rif->unk7C);
    memcpy(output.unk98, rif->unk80, sizeof(output.unk98));
    if (output.skuFlag == 2)
        output.skuFlag = 1;

    memcpy(DMEM + rif_pa + __builtin_offsetof(struct RifCmd56MemoryLayout, output), &output, sizeof(output));
    METRIC_INC(npdrm_mailbox_emulated);
#if KSTUFF_OBS
    if(s_current_ioctl_state.valid)
        observe_ioctl_com_emulated(s_current_ioctl_state.com, cmd);
#endif
    observe_current_syscall_emulated();

    uint32_t res = 0;
    if(copy_u32_to_kernel(regs[RDX] + 0x4, res))
    {
        uelf_fpu_exit();
        METRIC_INC(npdrm_reject_copy_out_fail);
        RETURN_NPDRM(1);
    }

    uelf_fpu_exit();
    regs[RIP] = lr;
    regs[RAX] = 0;
    regs[RSP] += 8;
    RETURN_NPDRM(1);
#undef RETURN_NPDRM
}

static const uint64_t dbgregs_for_ioctl[6] = {
    (uint64_t)sceSblServiceMailbox, 0, 0, 0,
    0, 0x401};

static uint8_t classify_npdrm_ioctl(uint64_t com)
{
    const uint32_t dir = (uint32_t)(com & IOC_DIRMASK);
    const uint32_t len = IOCPARM_LEN(com);
    const uint32_t group = IOCGROUP(com);
    const uint32_t num = (uint32_t)(com & 0xff);

    /*
     * Hot path from observed logs:
     *   IOC_INOUT + group 'N' (0x4e)
     * with the useful commands clustered in len=0x20 and len=0x34.
     *
     * Keep the rest of the known-good commands in the rare exact tail below
     * so coverage stays the same while the common case gets cheaper.
     */
    if(__builtin_expect(dir == IOC_INOUT && group == 0x4e, 1))
    {
        if(len == 0x20)
        {
            if(num == 0x0d || num == 0x0e)
                return NPDRM_EXPECT_CMD5 | NPDRM_EXPECT_CMD6;
            if(num == 0x16)
                return NPDRM_EXPECT_CMD6;
        }
        else if(len == 0x34 && num == 0x18)
            return NPDRM_EXPECT_CMD6;
    }

    switch(com)
    {
    case 0x000000004004ae25ULL:
    case 0x0000000040105305ULL:
    case 0x0000000080048138ULL:
    case 0x000000008008483eULL:
    case 0x000000008010480fULL:
    case 0x000000008018910bULL:
    case 0x0000000080206216ULL:
    case 0x0000000080208218ULL:
    case 0x0000000080283208ULL:
    case 0x0000000080308217ULL:
    case 0x00000000c0044512ULL:
    case 0x00000000c00c5a02ULL:
    case 0x00000000c0108102ULL:
    case 0x00000000c02066a5ULL:
    case 0x00000000c0288907ULL:
    case 0x00000000c0288908ULL:
    case 0x00000000c030ab00ULL:
    case 0x00000000c0484851ULL:
        return NPDRM_EXPECT_CMD5 | NPDRM_EXPECT_CMD6;
    default:
        return 0;
    }
}

void handle_ioctl_syscall(uint64_t *regs)
{
    struct ioctl_args uap;
    uint8_t expected_cmd_mask;
    if(copy_from_kernel(&uap, regs[RSI], sizeof(uap)))
    {
        finish_npdrm_ioctl_state();
#if KSTUFF_OBS
        METRIC_INC(ioctl_prefilter_copy_in_fail_open);
#endif
        start_syscall_with_dbgregs(regs, dbgregs_for_ioctl);
        return;
    }

#if KSTUFF_OBS
    s_current_ioctl_state.com = (uint64_t)uap.com;
#endif
    finish_npdrm_ioctl_state();

    expected_cmd_mask = classify_npdrm_ioctl((uint64_t)uap.com);
    if(!expected_cmd_mask)
    {
#if KSTUFF_OBS
        METRIC_INC(ioctl_prefilter_skipped);
#endif
        observe_current_syscall_finish();
        return;
    }

#if KSTUFF_OBS
    METRIC_INC(ioctl_prefilter_allowed);
    observe_ioctl_com_total(s_current_ioctl_state.com);
#endif
    s_current_ioctl_state.expected_cmd_mask = expected_cmd_mask;
    s_current_ioctl_state.valid = 1;
    start_syscall_with_dbgregs(regs, dbgregs_for_ioctl);
}
