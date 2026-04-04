#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include "utils.h"
#include "log.h"
#include "traps.h"
#include "kekcall.h"
#include "mailbox.h"
#include "fself.h"
#include "fpkg.h"
#include "syscall_fixes.h"
#include "npdrm.h"
#include "shared_area.h"

int have_error_code;

extern char syscall_before[];
extern char syscall_after[];
extern struct sysent sysents[];
extern struct sysent sysents_ps4[];
extern char doreti_iret[];
extern char ist4[];
extern char tss[];
extern char int1_handler[];
extern char int13_handler[];
extern uint64_t wrmsr_args;

void handle_syscall(uint64_t* regs, int allow_kekcall)
{
    const uint64_t syscall_extra = (FWVER >= 0x1000 ? 0x10 : 0);
#define IS_PPR(which) (regs[RAX] == (uint64_t)&sysents[SYS_##which])
#ifdef FREEBSD
#define IS_PS4(which) 0
#else
#define IS_PS4(which) (regs[RAX] == (uint64_t)&sysents_ps4[SYS_##which])
#endif
#define IS(which) (IS_PPR(which) || IS_PS4(which))
    if(IS_PPR(getppid) && allow_kekcall)
    {
        METRIC_INC(syscall_kekcall_dispatches);
        enum { KEKCALL_ARGS_OFFSET_MAX = syscall_rsp_to_regs_stash + 0x10 + 8 };
        uint8_t syscall_frame[KEKCALL_ARGS_OFFSET_MAX + sizeof(uint64_t) * NREGS];
        uint64_t args[NREGS] = {0};
        uint64_t args_offset = syscall_rsp_to_regs_stash + syscall_extra + 8;
        if(copy_from_kernel(syscall_frame, regs[RSP], args_offset + sizeof(args)))
            return;
        memcpy(args, syscall_frame + args_offset, sizeof(args));
        int err = handle_kekcall(regs, args, args[RAX]>>32);
        if(err != ENOSYS)
        {
            uint64_t syscall_lr = *(const uint64_t*)syscall_frame;
            if(!err)
                kpoke64(regs[RDI]+td_retval, args[RAX]);
            regs[RAX] = err;
            regs[RSP] += 8;
            regs[RIP] = syscall_lr;
        }
    }
#ifndef FREEBSD
    else if(IS(execve)
         || IS(dynlib_load_prx)
         || IS(get_self_auth_info)
         || IS(get_sdk_compiled_version)
         || IS_PPR(get_ppr_sdk_compiled_version)
#ifdef FIRMWARE_PORTING
         || IS_PPR(mmap)
         || IS_PPR(mlock)
#endif
    )
    {
        METRIC_INC(syscall_fself_dispatches);
        handle_fself_syscall(regs);
    }
    else if(IS(nmount)
         || IS(unmount))
    {
        METRIC_INC(syscall_fpkg_dispatches);
        handle_fpkg_syscall(regs);
    }
    else if(IS(ioctl)
         || IS_PPR(ioctl))
    {
        METRIC_INC(syscall_ioctl_dispatches);
        handle_ioctl_syscall(regs);
    }
    else if(IS(mprotect)
         || IS_PPR(mdbg_call))
    {
        METRIC_INC(syscall_fix_dispatches);
        handle_syscall_fix(regs);
    }
#endif
#undef IS
#undef IS_PS4
#undef IS_PPR
}

void handle(uint64_t* regs)
{
    METRIC_INC(handle_entries);
    const int initial_from_user = !!(regs[CS] & 3);
    const int initial_from_copyio = !!(regs[EFLAGS] & 0x40000);
    if(initial_from_user)
        METRIC_INC(handle_from_userspace_entries);
    const uint64_t syscall_extra = (FWVER >= 0x1000 ? 0x10 : 0);
    if(!initial_from_user)
        regs[EFLAGS] |= 0x10000; //RF
    if(initial_from_user || initial_from_copyio) //from userspace, or from copyin/copyout
    {
from_userspace:
        {
        const int from_user = !!(regs[CS] & 3);
        if(from_user) //from userspace
        {
            //determine correct gsbase for userspace
            uint64_t pcb;
            uint64_t gsbase;
            if(get_current_pcb_checked(&pcb))
                return;
            if(copy_from_kernel(&gsbase, get_pcb_field_ptr(pcb, pcb_gsbase), sizeof(gsbase)))
                return;
            //arm wrmsr in the exit path
            uint64_t args[3] = {gsbase >> 32, 0xc0000101, (uint32_t)gsbase};
            if(copy_to_kernel(wrmsr_args, args, sizeof(args)))
                return;
        }
        //inject a fake #DB or #GP exception
        uint64_t stack;
#ifndef FREEBSD
        if(!have_error_code)
            stack = (uint64_t)ist4;
        else
#endif
        {
            if(from_user)
            {
                if(copy_from_kernel(&stack, (uint64_t)tss+4, 8))
                    return;
            }
            else
                stack = regs[RSP];
        }
        stack &= -16;
        if(have_error_code)
        {
            stack -= 48;
            if(copy_to_kernel(stack, &regs[ERRC], 48))
                return;
            regs[RIP] = (uint64_t)int13_handler;
        }
        else
        {
            stack -= 40;
            if(copy_to_kernel(stack, &regs[RIP], 40))
                return;
            regs[RIP] = (uint64_t)int1_handler;
        }
        regs[CS] = 0x20;
        regs[EFLAGS] = 2;
        regs[RSP] = stack;
        regs[SS] = 0;
        }
    }
    else if(regs[RIP] == (uint64_t)syscall_before)
    {
        uint64_t syscall_target;
        regs[RAX] |= 0xffffull << 48;
        regs[RSI] = regs[RSP] + syscall_rsp_to_rsi + syscall_extra;
        if(copy_from_kernel(&syscall_target, regs[RAX]+8, sizeof(syscall_target)))
            return;
        if(push_stack_checked(regs, (const uint64_t[1]){(uint64_t)syscall_after}, 8))
            return;
        regs[RIP] = syscall_target;
        handle_syscall(regs, 1);
    }
    else if(regs[RIP] == (uint64_t)doreti_iret)
    {
        METRIC_INC(handle_doreti_iret_entries);
        uint64_t frame[5];
        if(copy_from_kernel(frame, regs[RSP], 16))
            return;
        if((frame[1] & 3)) //#GP in iret to userspace
        {
            //pretend that the #GP was inside userspace
            //stock kernel crashes on this, lol
            if(copy_from_kernel(frame + 2, regs[RSP] + 16, sizeof(frame) - 16))
                return;
            memcpy(&regs[RIP], frame, sizeof(frame));
            goto from_userspace;
        }
        uint64_t lr = frame[0];
        switch(TRAP_KIND(lr))
        {
        case TRAP_UTILS: handle_utils_trap(regs, TRAP_IDX(lr)); break;
        case TRAP_KEKCALL: handle_kekcall_trap(regs, TRAP_IDX(lr)); break;
#ifndef FREEBSD
        case TRAP_FSELF: handle_fself_trap(regs, TRAP_IDX(lr)); break;
        case TRAP_FPKG: handle_fpkg_trap(regs, TRAP_IDX(lr)); break;
#endif
        }
    }
#ifndef FREEBSD
    else if(try_handle_mailbox_trap(regs))
        return;
    else if(try_handle_fself_trap(regs))
    {
        METRIC_INC(fself_traps);
        return;
    }
    else if(try_handle_fpkg_trap(regs))
    {
        METRIC_INC(fpkg_traps);
        return;
    }
    else if(try_handle_syscall_fix_trap(regs))
    {
        METRIC_INC(syscall_fix_traps);
        return;
    }
#endif
    else
    {
        int decrypted = 0;
        uint32_t decrypt_mask = 0;
#define DECRYPT(which, bit, field) if((regs[which] >> 48) == 0xdeb7) { regs[which] |= 0xffffull << 48; decrypted = 1; decrypt_mask |= (1u << (bit)); METRIC_INC(debug_reg_decrypt_events); METRIC_INC(field); }
        DECRYPT(RAX, 0, debug_reg_decrypt_rax)
        DECRYPT(RCX, 1, debug_reg_decrypt_rcx)
        DECRYPT(RDX, 2, debug_reg_decrypt_rdx)
        DECRYPT(RBX, 3, debug_reg_decrypt_rbx)
        //DECRYPT(RSP, 4)
        DECRYPT(RBP, 5, debug_reg_decrypt_rbp)
        DECRYPT(RSI, 6, debug_reg_decrypt_rsi)
        DECRYPT(RDI, 7, debug_reg_decrypt_rdi)
        DECRYPT(R8, 8, debug_reg_decrypt_r8)
        DECRYPT(R9, 9, debug_reg_decrypt_r9)
        DECRYPT(R10, 10, debug_reg_decrypt_r10)
        DECRYPT(R11, 11, debug_reg_decrypt_r11)
        DECRYPT(R12, 12, debug_reg_decrypt_r12)
        DECRYPT(R13, 13, debug_reg_decrypt_r13)
        DECRYPT(R14, 14, debug_reg_decrypt_r14)
        DECRYPT(R15, 15, debug_reg_decrypt_r15)
#undef DECRYPT
        if(!decrypted)
        {
            //probably a debug trap that's not yet handled
            METRIC_INC(debug_unhandled_traps);
            log_msg("uelf: unhandled debug trap\n");
            log_word(regs[RIP]);
            log_word(16);
        }
        else if(decrypt_mask == (1u << 6))
            METRIC_INC(debug_reg_decrypt_rsi_only_events);
        else if(decrypt_mask & (1u << 6))
            METRIC_INC(debug_reg_decrypt_rsi_multi_events);
        else if(!(decrypt_mask & (decrypt_mask - 1)))
            METRIC_INC(debug_reg_decrypt_non_rsi_single_events);
        else
            METRIC_INC(debug_reg_decrypt_non_rsi_multi_events);
    }
}

void main(uint64_t just_return)
{
    uint64_t regs[NREGS];
    if(copy_from_kernel(regs, trap_frame, sizeof(regs)))
        return;
    uint64_t jr_frame[5];
    if(copy_from_kernel(jr_frame, just_return, 40))
        return;
    have_error_code = jr_frame[0];
    regs[RDX] = jr_frame[2];
    regs[RCX] = jr_frame[3];
    regs[RAX] = jr_frame[4];
    handle(regs);
    copy_to_kernel(trap_frame, regs, sizeof(regs));
}
