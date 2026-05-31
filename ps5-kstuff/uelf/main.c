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
#ifndef FREEBSD
extern char sceSblServiceMailbox[];
extern char sceSblServiceCryptAsync_deref_singleton[];
extern char sceSblAuthMgrSmIsLoadable2[];
extern char loadSelfSegment_watchpoint[];
extern char loadSelfSegment_epilogue[];
extern char decryptSelfBlock_epilogue[];
extern char decryptMultipleSelfBlocks_epilogue[];
extern char mprotect_fix_start[];
#endif

void handle_syscall(uint64_t* regs, int allow_kekcall)
{
    METRIC_TIME_START(start_cycles);
    const uint64_t sysent = regs[RAX];
    observe_syscall_armed(KSTUFF_SYSCALL_NONE);
#define RETURN_HANDLE_SYSCALL() do { METRIC_TIME(handle_syscall_cycles_total, handle_syscall_cycles_max, start_cycles); return; } while(0)
#define IS_PPR(which) (sysent == (uint64_t)&sysents[SYS_##which])
#ifdef FREEBSD
#define IS_PS4(which) 0
#else
    #define IS_PS4(which) (sysent == (uint64_t)&sysents_ps4[SYS_##which])
    if(IS_PPR(ioctl) || IS_PS4(ioctl))
    {
        METRIC_INC(syscall_ioctl_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_IOCTL);
        handle_ioctl_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
#endif
#define IS(which) (IS_PPR(which) || IS_PS4(which))
    if(allow_kekcall && IS_PPR(getppid))
    {
        METRIC_INC(syscall_kekcall_dispatches);
        enum { KEKCALL_ARGS_OFFSET_MAX = syscall_rsp_to_regs_stash + 0x10 + 8 };
        uint8_t syscall_frame[KEKCALL_ARGS_OFFSET_MAX + sizeof(uint64_t) * NREGS];
        uint64_t args[NREGS] = {0};
        const uint64_t syscall_extra = (FWVER >= 0x1000 ? 0x10 : 0);
        uint64_t args_offset = syscall_rsp_to_regs_stash + syscall_extra + 8;
        if(copy_from_kernel(syscall_frame, regs[RSP], args_offset + sizeof(args)))
            RETURN_HANDLE_SYSCALL();
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
        RETURN_HANDLE_SYSCALL();
    }
#ifndef FREEBSD
    if(IS(mprotect)
         || IS_PPR(mdbg_call))
    {
        METRIC_INC(syscall_fix_dispatches);
        observe_syscall_armed(IS(mprotect) ? KSTUFF_SYSCALL_MPROTECT : KSTUFF_SYSCALL_MDBG_CALL);
        handle_syscall_fix(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(nmount))
    {
        METRIC_INC(syscall_fpkg_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_NMOUNT);
        handle_fpkg_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(unmount))
    {
        METRIC_INC(syscall_fpkg_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_UNMOUNT);
        handle_fpkg_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(execve))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_EXECVE);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(dynlib_load_prx))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_DYNLIB_LOAD_PRX);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(get_self_auth_info))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_GET_SELF_AUTH_INFO);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS(get_sdk_compiled_version))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_GET_SDK_COMPILED_VERSION);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS_PPR(get_ppr_sdk_compiled_version))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_GET_PPR_SDK_COMPILED_VERSION);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
#ifdef FIRMWARE_PORTING
    if(IS_PPR(mmap))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_MMAP);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
    if(IS_PPR(mlock))
    {
        METRIC_INC(syscall_fself_dispatches);
        observe_syscall_armed(KSTUFF_SYSCALL_MLOCK);
        handle_fself_syscall(regs);
        RETURN_HANDLE_SYSCALL();
    }
#endif
#endif
#undef IS
#undef IS_PS4
#undef IS_PPR
#undef RETURN_HANDLE_SYSCALL
    METRIC_TIME(handle_syscall_cycles_total, handle_syscall_cycles_max, start_cycles);
}

static inline int handle_generic_decrypt_trap(uint64_t* regs)
{
    METRIC_TIME_START(start_cycles);
    const uint64_t poisoned_hi = 0xdeb7;
    const uint64_t restore_hi = 0xffffull << 48;
#define IS_POISONED(which) ((regs[which] >> 48) == poisoned_hi)
#define FIX_POISONED(which, field) do { regs[which] |= restore_hi; METRIC_INC(debug_reg_decrypt_events); METRIC_INC(field); } while(0)
#define RETURN_GENERIC_DECRYPT(value) do { METRIC_TIME(generic_decrypt_cycles_total, generic_decrypt_cycles_max, start_cycles); return (value); } while(0)
    /*
     * Telemetry shows that almost every generic decrypt fixup is RSI-only.
     * The only other registers that show up with non-trivial frequency are
     * RAX, RDX, RDI and R10, so keep them in the hot tail and push the rest
     * into a colder fallback path to reduce work on the dominant case.
     */
    if(__builtin_expect(IS_POISONED(RSI), 1))
    {
        int hot_other_poisoned =
            IS_POISONED(RAX) | IS_POISONED(RDX) | IS_POISONED(RDI) | IS_POISONED(R10);
        FIX_POISONED(RSI, debug_reg_decrypt_rsi);
        if(__builtin_expect(!hot_other_poisoned, 1))
        {
            int cold_other_poisoned =
                IS_POISONED(RCX) | IS_POISONED(RBX) | IS_POISONED(RBP) |
                IS_POISONED(R8)  | IS_POISONED(R9)  | IS_POISONED(R11) |
                IS_POISONED(R12) | IS_POISONED(R13) | IS_POISONED(R14) |
                IS_POISONED(R15);
            if(__builtin_expect(!cold_other_poisoned, 1))
            {
                METRIC_INC(debug_reg_decrypt_rsi_only_events);
                RETURN_GENERIC_DECRYPT(1);
            }
            METRIC_INC(debug_reg_decrypt_rsi_multi_events);
            if(IS_POISONED(RCX)) FIX_POISONED(RCX, debug_reg_decrypt_rcx);
            if(IS_POISONED(RBX)) FIX_POISONED(RBX, debug_reg_decrypt_rbx);
            if(IS_POISONED(RBP)) FIX_POISONED(RBP, debug_reg_decrypt_rbp);
            if(IS_POISONED(R8)) FIX_POISONED(R8, debug_reg_decrypt_r8);
            if(IS_POISONED(R9)) FIX_POISONED(R9, debug_reg_decrypt_r9);
            if(IS_POISONED(R11)) FIX_POISONED(R11, debug_reg_decrypt_r11);
            if(IS_POISONED(R12)) FIX_POISONED(R12, debug_reg_decrypt_r12);
            if(IS_POISONED(R13)) FIX_POISONED(R13, debug_reg_decrypt_r13);
            if(IS_POISONED(R14)) FIX_POISONED(R14, debug_reg_decrypt_r14);
            if(IS_POISONED(R15)) FIX_POISONED(R15, debug_reg_decrypt_r15);
            RETURN_GENERIC_DECRYPT(1);
        }
        METRIC_INC(debug_reg_decrypt_rsi_multi_events);
        if(IS_POISONED(RAX)) FIX_POISONED(RAX, debug_reg_decrypt_rax);
        if(IS_POISONED(RDX)) FIX_POISONED(RDX, debug_reg_decrypt_rdx);
        if(IS_POISONED(RDI)) FIX_POISONED(RDI, debug_reg_decrypt_rdi);
        if(IS_POISONED(R10)) FIX_POISONED(R10, debug_reg_decrypt_r10);
        if(__builtin_expect(
            IS_POISONED(RCX) | IS_POISONED(RBX) | IS_POISONED(RBP) |
            IS_POISONED(R8)  | IS_POISONED(R9)  | IS_POISONED(R11) |
            IS_POISONED(R12) | IS_POISONED(R13) | IS_POISONED(R14) |
            IS_POISONED(R15), 0))
        {
            if(IS_POISONED(RCX)) FIX_POISONED(RCX, debug_reg_decrypt_rcx);
            if(IS_POISONED(RBX)) FIX_POISONED(RBX, debug_reg_decrypt_rbx);
            if(IS_POISONED(RBP)) FIX_POISONED(RBP, debug_reg_decrypt_rbp);
            if(IS_POISONED(R8)) FIX_POISONED(R8, debug_reg_decrypt_r8);
            if(IS_POISONED(R9)) FIX_POISONED(R9, debug_reg_decrypt_r9);
            if(IS_POISONED(R11)) FIX_POISONED(R11, debug_reg_decrypt_r11);
            if(IS_POISONED(R12)) FIX_POISONED(R12, debug_reg_decrypt_r12);
            if(IS_POISONED(R13)) FIX_POISONED(R13, debug_reg_decrypt_r13);
            if(IS_POISONED(R14)) FIX_POISONED(R14, debug_reg_decrypt_r14);
            if(IS_POISONED(R15)) FIX_POISONED(R15, debug_reg_decrypt_r15);
        }
        RETURN_GENERIC_DECRYPT(1);
    }
    else
    {
        int hot_fixed = 0;
        int cold_fixed = 0;
        if(IS_POISONED(RAX)) { FIX_POISONED(RAX, debug_reg_decrypt_rax); hot_fixed++; }
        if(IS_POISONED(RDX)) { FIX_POISONED(RDX, debug_reg_decrypt_rdx); hot_fixed++; }
        if(IS_POISONED(RDI)) { FIX_POISONED(RDI, debug_reg_decrypt_rdi); hot_fixed++; }
        if(IS_POISONED(R10)) { FIX_POISONED(R10, debug_reg_decrypt_r10); hot_fixed++; }
        if(__builtin_expect(
            IS_POISONED(RCX) | IS_POISONED(RBX) | IS_POISONED(RBP) |
            IS_POISONED(R8)  | IS_POISONED(R9)  | IS_POISONED(R11) |
            IS_POISONED(R12) | IS_POISONED(R13) | IS_POISONED(R14) |
            IS_POISONED(R15), 0))
        {
            if(IS_POISONED(RCX)) { FIX_POISONED(RCX, debug_reg_decrypt_rcx); cold_fixed++; }
            if(IS_POISONED(RBX)) { FIX_POISONED(RBX, debug_reg_decrypt_rbx); cold_fixed++; }
            if(IS_POISONED(RBP)) { FIX_POISONED(RBP, debug_reg_decrypt_rbp); cold_fixed++; }
            if(IS_POISONED(R8)) { FIX_POISONED(R8, debug_reg_decrypt_r8); cold_fixed++; }
            if(IS_POISONED(R9)) { FIX_POISONED(R9, debug_reg_decrypt_r9); cold_fixed++; }
            if(IS_POISONED(R11)) { FIX_POISONED(R11, debug_reg_decrypt_r11); cold_fixed++; }
            if(IS_POISONED(R12)) { FIX_POISONED(R12, debug_reg_decrypt_r12); cold_fixed++; }
            if(IS_POISONED(R13)) { FIX_POISONED(R13, debug_reg_decrypt_r13); cold_fixed++; }
            if(IS_POISONED(R14)) { FIX_POISONED(R14, debug_reg_decrypt_r14); cold_fixed++; }
            if(IS_POISONED(R15)) { FIX_POISONED(R15, debug_reg_decrypt_r15); cold_fixed++; }
        }
        if(hot_fixed | cold_fixed)
        {
            if(hot_fixed + cold_fixed == 1)
                METRIC_INC(debug_reg_decrypt_non_rsi_single_events);
            else
                METRIC_INC(debug_reg_decrypt_non_rsi_multi_events);
            RETURN_GENERIC_DECRYPT(1);
        }
    }
#undef FIX_POISONED
#undef IS_POISONED
    METRIC_INC(debug_unhandled_traps);
    log_msg("uelf: unhandled debug trap\n");
    log_word(regs[RIP]);
    log_word(16);
    RETURN_GENERIC_DECRYPT(1);
}

#ifndef FREEBSD
static inline int is_fself_trap_rip(uint64_t rip)
{
    return rip == (uint64_t)sceSblAuthMgrSmIsLoadable2
        || rip == (uint64_t)loadSelfSegment_watchpoint
        || rip == (uint64_t)loadSelfSegment_epilogue
        || rip == (uint64_t)decryptSelfBlock_epilogue
        || rip == (uint64_t)decryptMultipleSelfBlocks_epilogue;
}

static inline int handle_kernel_trap_fast(uint64_t* regs, uint64_t rip)
{
    if(rip == (uint64_t)sceSblServiceMailbox)
        return try_handle_mailbox_trap(regs);
    if(rip == (uint64_t)sceSblServiceCryptAsync_deref_singleton)
    {
        if(try_handle_fpkg_trap(regs))
        {
            METRIC_INC(fpkg_traps);
            observe_current_syscall_trap();
            return 1;
        }
    }
    if(is_fself_trap_rip(rip))
    {
        int fself_result = try_handle_fself_trap(regs);
        if(fself_result & FSELF_HANDLE_HANDLED)
        {
            METRIC_INC(fself_traps);
            observe_current_syscall_trap();
            if(fself_result & FSELF_HANDLE_EMULATED)
                observe_current_syscall_emulated();
            return 1;
        }
    }
    if(rip == (uint64_t)mprotect_fix_start || rip == (uint64_t)aslr_fix_start)
    {
        if(try_handle_syscall_fix_trap(regs))
        {
            METRIC_INC(syscall_fix_traps);
            observe_current_syscall_trap();
            observe_current_syscall_emulated();
            return 1;
        }
    }
    return handle_generic_decrypt_trap(regs);
}
#endif

void handle(uint64_t* regs)
{
    METRIC_TIME_START(start_cycles);
#define RETURN_HANDLE() do { METRIC_TIME(handle_cycles_total, handle_cycles_max, start_cycles); return; } while(0)
    METRIC_INC(handle_entries);
    const int initial_from_user = !!(regs[CS] & 3);
    const int initial_from_copyio = !!(regs[EFLAGS] & 0x40000);
    const uint64_t rip = regs[RIP];
    if(initial_from_user)
        METRIC_INC(handle_from_userspace_entries);
    if(!initial_from_user)
        regs[EFLAGS] |= 0x10000; //RF
    if(__builtin_expect(!initial_from_user && !initial_from_copyio, 1)
    && __builtin_expect(rip != (uint64_t)syscall_before && rip != (uint64_t)doreti_iret, 1))
    {
#ifndef FREEBSD
        handle_kernel_trap_fast(regs, rip);
#else
        handle_generic_decrypt_trap(regs);
#endif
        RETURN_HANDLE();
    }
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
                RETURN_HANDLE();
            if(copy_from_kernel(&gsbase, get_pcb_field_ptr(pcb, pcb_gsbase), sizeof(gsbase)))
                RETURN_HANDLE();
            //arm wrmsr in the exit path
            uint64_t args[3] = {gsbase >> 32, 0xc0000101, (uint32_t)gsbase};
            if(copy_to_kernel(wrmsr_args, args, sizeof(args)))
                RETURN_HANDLE();
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
                if(copy_u64_from_kernel(&stack, (uint64_t)tss + 4))
                    RETURN_HANDLE();
            }
            else
                stack = regs[RSP];
        }
        stack &= -16;
        if(have_error_code)
        {
            stack -= 48;
            if(copy_to_kernel(stack, &regs[ERRC], 48))
                RETURN_HANDLE();
            regs[RIP] = (uint64_t)int13_handler;
        }
        else
        {
            stack -= 40;
            if(copy_to_kernel(stack, &regs[RIP], 40))
                RETURN_HANDLE();
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
        const uint64_t syscall_extra = (FWVER >= 0x1000 ? 0x10 : 0);
        uint64_t syscall_target;
        regs[RAX] |= 0xffffull << 48;
        regs[RSI] = regs[RSP] + syscall_rsp_to_rsi + syscall_extra;
        if(copy_u64_from_kernel(&syscall_target, regs[RAX] + 8))
            RETURN_HANDLE();
        if(push_stack_checked(regs, (const uint64_t[1]){(uint64_t)syscall_after}, 8))
            RETURN_HANDLE();
        regs[RIP] = syscall_target;
        handle_syscall(regs, 1);
    }
    else if(regs[RIP] == (uint64_t)doreti_iret)
    {
        METRIC_INC(handle_doreti_iret_entries);
        uint64_t frame[5];
        if(copy_from_kernel(frame, regs[RSP], 16))
            RETURN_HANDLE();
        if((frame[1] & 3)) //#GP in iret to userspace
        {
            //pretend that the #GP was inside userspace
            //stock kernel crashes on this, lol
            if(copy_from_kernel(frame + 2, regs[RSP] + 16, sizeof(frame) - 16))
                RETURN_HANDLE();
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
#undef RETURN_HANDLE
    METRIC_TIME(handle_cycles_total, handle_cycles_max, start_cycles);
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
