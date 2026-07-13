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
extern char sceSblServiceMailbox_lr_verifyImage[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_1[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_2[];
extern char sceSblServiceRequest_lr_registerMountKey_1[];
extern char sceSblServiceRequest_lr_registerMountKey_2[];
extern char sceSblServiceCryptAsync_deref_singleton[];
extern char crypt_message_resolve[];
extern char doreti_iret[];

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

static int read_crypto_message(uint64_t msg, uint64_t msg_data[21])
{
    return copy_from_kernel(msg_data, msg, sizeof(uint64_t) * 21);
}

static int is_hmac_message(const uint64_t msg_data[21])
{
    return (msg_data[0] & 0x7fffffff) == 0x9132000;
}

static int is_xts_message(const uint64_t msg_data[21])
{
    return (msg_data[0] & 0x7ffff7ff) == 0x2108000;
}

static struct crypto_message_result unhandled_crypto_message(uint64_t msg)
{
    return (struct crypto_message_result){
        .emulated_messages = 0,
        .next_msg = kpeek64(msg + 320),
        .status = ENOSYS,
        .total_messages = 1,
    };
}

static struct crypto_message_info inspect_crypto_message(const uint64_t msg_data[21])
{
    if(is_xts_message(msg_data))
    {
        int key_idx = HANDLE_TO_IDX(msg_data[5]);
        if(key_idx < 0 || !has_fake_key(key_idx))
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
        else if(key_idx < 0 || !has_fake_key(key_idx))
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

static struct crypto_message_result handle_hmac_message(uint64_t msg, const uint64_t msg_data[21],
                                                        int key_idx,
                                                        struct crypto_request_cache* cache)
{
    struct crypto_message_result result = unhandled_crypto_message(msg);
    uint8_t key[32];
    if(!get_fake_key(key_idx, key))
        return result;

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

static struct crypto_message_result handle_xts_message(uint64_t msg, const uint64_t msg_data[21],
                                                       int key_idx,
                                                       struct crypto_request_cache* cache)
{
    struct crypto_message_result result = unhandled_crypto_message(msg);
    uint8_t key[32];
    if(!get_fake_key(key_idx, key))
        return result;
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

    uint64_t start = (FWVER >= 0x800) ? regs[RBX] : regs[R14];

    for (uint64_t msg = start; msg && !total_status;)
    {
        uint64_t msg_data[21];
        if(read_crypto_message(msg, msg_data))
        {
            total_status = -1;
            break;
        }

        struct crypto_message_info msg_info = inspect_crypto_message(msg_data);
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
            result = handle_xts_message(msg, msg_data, msg_info.key_idx, &s_crypto_request_cache);
        else if(msg_info.kind == CRYPTO_MESSAGE_HMAC)
            result = handle_hmac_message(msg, msg_data, msg_info.key_idx, &s_crypto_request_cache);
        else
            result = unhandled_crypto_message(msg);
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
    else
        return 0;
    return 1;
}

int try_handle_fpkg_mailbox(uint64_t* regs, uint64_t lr)
{
    if(lr == (uint64_t)sceSblServiceMailbox_lr_verifySuperBlock)
    {
        METRIC_INC(verify_superblock_mailbox);
        uint64_t req[8];
        if(copy_from_kernel(req, regs[RDX], 64))
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
	else if(lr == (uint64_t)sceSblServiceMailbox_lr_verifyImage)
	{
		//just a start, not really sure how this goes yet
		METRIC_INC(verify_image_mailbox);

		uint64_t req[8] = {0};

		if(copy_from_kernel(req, regs[RDX], sizeof(req)))
			return 0;

		uint64_t resp[8] = {0};

		resp[0] = 0;   // success

		if(copy_to_kernel(regs[RDX], resp, sizeof(resp)))
			return 0;

		regs[RIP] = lr;
		regs[RAX] = 0;
		regs[RSP] += 8;

		METRIC_INC(verify_image_emulated);
		observe_current_syscall_emulated();

		return 1;
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
        uint64_t frame[12];
        if(pop_stack_checked(regs, frame, sizeof(frame)))
            return;
        regs[RBX] = frame[7];
        regs[R14] = frame[8];
        regs[R15] = frame[9];
        regs[RBP] = frame[10];
        regs[RIP] = frame[11];
        regs[RAX] = 0;
    }
}

static const uint64_t dbgregs_for_nmount[6] = {
    (uint64_t)sceSblServiceMailbox, 0, 0, 0,
    0, 0x401
};

void handle_fpkg_syscall(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_nmount);
}
