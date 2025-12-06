#include <string.h>
#include <errno.h>
#include "fself.h"
#include "utils.h"
#include "traps.h"
#include "log.h"
#include "syscall_fixes.h"

#ifndef FREEBSD

static uint64_t s_auth_info_for_dynlib[17] = {0x4900000000000002, 0x0000000000000000, 0x800000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x7000700080000000, 0x8000000000000000, 0x0000000000000000, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
static uint64_t s_auth_info_for_exec[17] = {0x4400001084c2052d, 0x2000038000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};

static uint64_t s_auth_info_for_dynlib_ps4[17] = {0x3100000000000002, 0x0000000000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x3000300040000000, 0x4000000000000000, 0x0080000000000000, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
static uint64_t s_auth_info_for_exec_ps4[17] = {0x3100000000000001, 0x2000038000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};

static int copy_from_kernel_buffer(void* dst, uint64_t src, uint64_t src_end, uint64_t offset, size_t sz)
{
    if(src + offset < src || src + offset > src_end)
        return EFAULT;
    if(src + offset + sz < src + offset || src + offset + sz > src_end)
        return EFAULT;
    return copy_from_kernel(dst, src + offset, sz);
}

static int is_header_fself(uint64_t header, uint32_t size, uint16_t* e_type, int* is_ps4, uint64_t* authinfo, int* have_authinfo)
{
    uint64_t header_end = header + size;
    uint16_t n_entries;
    if(copy_from_kernel_buffer(&n_entries, header, header_end, 24, sizeof(n_entries)))
        return 0;
    uint64_t elf_offset = 32 + 32 * n_entries;
    uint64_t elf[8];
    if(copy_from_kernel_buffer(elf, header, header_end, elf_offset, sizeof(elf)))
        return 0;
    if(e_type)
        *e_type = elf[2];
    if(is_ps4)
        *is_ps4 = (uint8_t)elf[1] < 2;
    uint64_t e_phoff = elf[4];
    uint16_t e_phnum = elf[7];
    uint64_t ex_offset = elf_offset + e_phoff + 56 * e_phnum;
    ex_offset = ((ex_offset - 1) | 15) + 1;
    uint64_t ex[4];
    if(copy_from_kernel_buffer(ex, header, header_end, ex_offset, sizeof(ex)))
        return 0;
    if(ex[1] != 1) //not fself
        return 0;
    if(have_authinfo)
    {
        *have_authinfo = 0;
        uint64_t sig_off = ex_offset + 64 + 48 + n_entries * 80 + 80;
        uint64_t signature[18] = {0};
        if(!copy_from_kernel_buffer(signature, header, header_end, sig_off, sizeof(signature)) && signature[0] == 0x88)
        {
            memcpy(authinfo, signature+1, 0x88);
            *have_authinfo = 1;
        }
    }
    return 1;
}

extern char doreti_iret[];
extern char sceSblAuthMgrSmIsLoadable2[];
extern char sceSblServiceMailbox[];
extern char sceSblServiceMailbox_lr_verifyHeader[];
extern char sceSblServiceMailbox_lr_loadSelfSegment[];
extern char sceSblServiceMailbox_lr_decryptSelfBlock[];
extern char sceSblServiceMailbox_lr_decryptMultipleSelfBlocks[];
extern char loadSelfSegment_watchpoint[];
extern char loadSelfSegment_watchpoint_lr[];
extern char loadSelfSegment_epilogue[];
extern char decryptSelfBlock_watchpoint_lr[];
extern char decryptSelfBlock_epilogue[];
extern char decryptMultipleSelfBlocks_watchpoint_lr[];
extern char decryptMultipleSelfBlocks_epilogue[];
extern char mini_syscore_header[];

static void set_dbgregs_for_watchpoint(uint64_t* regs, const uint64_t* dbgregs, size_t frame_size)
{
    uint64_t buf[frame_size/8 + 6];
    pop_stack(regs, buf, frame_size);
    read_dbgregs(buf + frame_size/8);
    push_stack(regs, buf, sizeof(buf));
    set_pcb_dbregs();
    write_dbgregs(dbgregs);
}

static void unset_dbgregs_for_watchpoint(uint64_t* regs)
{
    uint64_t dbgregs[6];
    pop_stack(regs, dbgregs, sizeof(dbgregs));
    write_dbgregs(dbgregs);
}

#ifdef FIRMWARE_PORTING
extern char mmap_self_fix_1_start[];
extern char mmap_self_fix_2_start[];
extern char mmap_self_fix_1_end[];
extern char mmap_self_fix_2_end[];
#endif

static uint64_t dbgregs_for_fself[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)sceSblAuthMgrSmIsLoadable2,
#ifdef FIRMWARE_PORTING
    (uint64_t)mmap_self_fix_1_start, (uint64_t)mmap_self_fix_2_start,
    0, 0x455,
#else
    (uint64_t) aslr_fix_start, 0,
    0, 0x415,
#endif
};

static uint64_t dbgregs_for_loadSelfSegment[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)loadSelfSegment_epilogue, 0, 0,
    0, 0x405,
};

static uint64_t dbgregs_for_decryptSelfBlock[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)decryptSelfBlock_epilogue, 0, 0,
    0, 0x405,
};

static uint64_t dbgregs_for_decryptMultipleSelfBlocks[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)decryptMultipleSelfBlocks_epilogue, 0, 0,
    0, 0x405,
};

void handle_fself_syscall(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_fself);
}

void handle_fself_trap(uint64_t* regs, uint32_t trapno)
{
    if (trapno == 1)
    {
		uint64_t self_header = kpeek64(regs[(fwver >= 0x800) ? RBX : R14] + 56);

        char fself_header_backup[(48 + mini_syscore_header_size + 15) & -16];
        pop_stack(regs, fself_header_backup, sizeof(fself_header_backup));

        regs[RIP] = *(uint64_t*)(fself_header_backup + sizeof(fself_header_backup) - 8);

        copy_to_kernel(self_header, fself_header_backup + 40, mini_syscore_header_size);
    }
}


int try_handle_fself_mailbox(uint64_t* regs, uint64_t lr)
{
    if(lr == (uint64_t)sceSblServiceMailbox_lr_verifyHeader)
    {
		uint64_t self_header = kpeek64(regs[(fwver >= 0x800) ? RBX : R14] + 56);
		uint32_t size;
        copy_from_kernel(&size, regs[RDX]+16, 4);
        if(is_header_fself(self_header, size, 0, 0, 0, 0))
        {
            char fself_header_backup[(48 + mini_syscore_header_size + 15) & -16];
            uint64_t trap_frame[6] = {
                (uint64_t)doreti_iret,
                MKTRAP(TRAP_FSELF, 1), 0, 0, 0, 0,
            };
            memcpy(fself_header_backup, trap_frame, 48);
            copy_from_kernel(fself_header_backup+48, self_header, mini_syscore_header_size);
            push_stack(regs, fself_header_backup, sizeof(fself_header_backup));
            copy_from_kernel(fself_header_backup+48, (uint64_t)mini_syscore_header, mini_syscore_header_size);
            copy_to_kernel(self_header, fself_header_backup+48, mini_syscore_header_size);
            size = mini_syscore_header_size;
            copy_to_kernel(regs[RDX]+16, &size, 4);
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_loadSelfSegment)
    {
        uint64_t ctx[8];
		copy_from_kernel(
    		ctx,
    		(fwver >= 0x1000) ? kpeek64(regs[RBP] - 232) :
    		(fwver >= 0x900) ? regs[R14] :
    		(fwver >= 0x800 && fwver <= 0x860) ? kpeek64(regs[RBP] - 240) :
    		regs[RBX],
    		sizeof(ctx)
		);

        if(is_header_fself(ctx[7], (uint32_t)ctx[1], 0, 0, 0, 0))
        {
            pop_stack(regs, &regs[RIP], 8);
            regs[RAX] = 0;
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_decryptSelfBlock)
    {
        uint64_t ctx[8];
		copy_from_kernel(
    		ctx,
    		(fwver >= 0x800) ? regs[R12] :
    		(fwver >= 0x500 && fwver <= 0x761) ? kpeek64(regs[RBP] - 192) :
    		kpeek64(regs[RBP] - sceSblServiceMailbox_decryptSelfBlock_rsp_to_rbp +
                     		sceSblServiceMailbox_decryptSelfBlock_rsp_to_self_context),
    		sizeof(ctx)
		);

        if(is_header_fself(ctx[7], (uint32_t)ctx[1], 0, 0, 0, 0))
        {
            uint64_t request[8];
            copy_from_kernel(request, regs[RDX], sizeof(request));
            memcpy(DMEM+request[1], DMEM+request[2], (uint32_t)request[6]);
            pop_stack(regs, &regs[RIP], 8);
            regs[RAX] = 0;
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_decryptMultipleSelfBlocks)
    {
        uint64_t ctx[8];
		copy_from_kernel(
    		ctx,
    		(fwver >= 0x600) ? kpeek64(regs[RBP] - 208) :
    		(fwver >= 0x500 && fwver <= 0x550) ? kpeek64(regs[RBP] - 216) :
    		regs[R13],
    		sizeof(ctx)
		);
        
        if(is_header_fself(ctx[7], (uint32_t)ctx[1], 0, 0, 0, 0))
        {
            uint64_t request[8];
            copy_from_kernel(request, regs[RDX], sizeof(request));
            uint64_t* src = (uint64_t*)(DMEM + request[1]);
            uint64_t* dst = (uint64_t*)(DMEM + request[2]);
            uint32_t count = request[5];
            for(uint32_t i = 0; i < count; i++)
                memcpy(DMEM+dst[i], DMEM+src[i], 16384);
            pop_stack(regs, &regs[RIP], 8);
            regs[RAX] = 0;
        }
    }
    else
        return 0;

    return 1;
}

int try_handle_fself_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblAuthMgrSmIsLoadable2)
    {
        uint64_t ctx[8];
        copy_from_kernel(ctx, regs[RDI], sizeof(ctx));
        uint16_t e_type;
        int have_authinfo;
        uint64_t authinfo[17];
        int is_ps4;
        if(is_header_fself(ctx[7], (uint32_t)ctx[1], &e_type, &is_ps4, authinfo, &have_authinfo))
        {
            uint64_t* p_authinfo;
            if(have_authinfo)
                p_authinfo = authinfo;
            else if(is_ps4)
            {
                if(e_type == 0xfe18)
                    p_authinfo = s_auth_info_for_dynlib_ps4;
                else
                    p_authinfo = s_auth_info_for_exec_ps4;
            }
            else
            {
                if(e_type == 0xfe18)
                    p_authinfo = s_auth_info_for_dynlib;
                else
                    p_authinfo = s_auth_info_for_exec;
            }
            copy_to_kernel(regs[R8], p_authinfo, 0x88);
            pop_stack(regs, &regs[RIP], 8);
            regs[RAX] = 0;
            copy_to_kernel(regs[RDI] + 62, &(const uint16_t[1]){0xdeb7}, 2);  
        }
    }
    else if(regs[RIP] == (uint64_t)loadSelfSegment_watchpoint)
    {
        regs[(fwver >= 0x800) ? RAX : R10] |= 0xffffull << 48;
		
        uint64_t frame[4];
        copy_from_kernel(frame, regs[RSP], sizeof(frame));
        if(frame[3] == (uint64_t)loadSelfSegment_watchpoint_lr)
            set_dbgregs_for_watchpoint(regs, dbgregs_for_loadSelfSegment, sizeof(frame));
        else if(frame[3] == (uint64_t)decryptSelfBlock_watchpoint_lr)
            set_dbgregs_for_watchpoint(regs, dbgregs_for_decryptSelfBlock, sizeof(frame));
        else if(frame[3] == (uint64_t)decryptMultipleSelfBlocks_watchpoint_lr)
            set_dbgregs_for_watchpoint(regs, dbgregs_for_decryptMultipleSelfBlocks, sizeof(frame));
    }
    else if(regs[RIP] == (uint64_t)loadSelfSegment_epilogue
         || regs[RIP] == (uint64_t)decryptSelfBlock_epilogue
         || regs[RIP] == (uint64_t)decryptMultipleSelfBlocks_epilogue)
         unset_dbgregs_for_watchpoint(regs);
#ifdef FIRMWARE_PORTING
    else if(regs[RIP] == (uint64_t)mmap_self_fix_1_start)
        regs[RIP] = (uint64_t)mmap_self_fix_1_end;
    else if(regs[RIP] == (uint64_t)mmap_self_fix_2_start)
        regs[RIP] = (uint64_t)mmap_self_fix_2_end;
#endif
    else
        return 0;
    return 1;
}

#endif