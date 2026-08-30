#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <machine/sysarch.h>
#include <string.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"
#include "log.h"
#if KSTUFF_SELF_ELEVATION
#include "self_elevation.h"
#endif

extern char syscall_after[];
extern char doreti_iret[];
extern char nop_ret[];
extern char copyout[];
extern char copyin[];
extern struct sysent sysents[];

int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)
{
    if(nr == 1)
    {
        uint64_t stack_frame[12] = {
            (uint64_t)doreti_iret,
            (uint64_t)nop_ret, regs[CS], regs[EFLAGS], regs[RSP], regs[SS],
        };
        int have_dbgregs;
        if(read_dbgregs_checked(stack_frame+6))
            return EFAULT;
        if(get_pcb_dbregs_checked(&have_dbgregs))
            return EFAULT;
        if(!have_dbgregs)
        {
            stack_frame[6] = stack_frame[7] = stack_frame[8] = stack_frame[9] = 0;
            stack_frame[10] &= -16;
        }
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        if(copy_to_kernel(regs[RDI]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
        {
            regs[RSP] += sizeof(stack_frame);
            return EFAULT;
        }
        regs[RDI] = regs[RSP] + 48;
        regs[RSI] = args[RDI];
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyout;
    }
    else if(nr == 2)
    {
        uint64_t stack_frame[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 1), [12] = regs[RDI]};
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        regs[RDI] = args[RDI];
        regs[RSI] = regs[RSP] + 48;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 3)
    {
        return rdmsr(args[RDI], &args[RAX]) ? 0 : EFAULT;
    }
    //nr 4 reserved for wrmsr
    else if(nr == 5) //remote syscall
    {
        uint64_t stack_frame[16] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 2)};
        stack_frame[6] = args[RDI];
        stack_frame[7] = args[RSI];
        stack_frame[14] = regs[RDI];
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        regs[RDI] = args[RDX];
        regs[RSI] = regs[RSP] + 64;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 6)
    {
#if KSTUFF_OBS
        int err = copy_shared_area_snapshot(args[RDI], args[RSI]);
        if(!err)
        {
            args[RAX] = 0;
            METRIC_INC(shared_area_snapshots);
        }
        return err;
#else
        return ENOSYS;
#endif
    }
#if KSTUFF_SELF_ELEVATION
    else if(nr == KSTUFF_SELF_ELEVATION_OP)
    {
        int err = elevate_current_process(regs[RDI], args[RDI], args[RSI], args[RDX]);
        if(!err)
            args[RAX] = 0;
        return err;
    }
#endif
   else if(nr == 0xffffffff)
    {
        args[RAX] = 0;
        return 0;
    }
    return ENOSYS;
}

void handle_kekcall_trap(uint64_t* regs, uint32_t trap)
{
    if(trap == 1)
    {
        uint64_t stack_frame[14];
        uint64_t old_dbgregs[6];
        uint64_t p_pcb_flags;
        uint64_t pcb_flags_value;
        int had_dbgregs;
        if(pop_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return;
        regs[RIP] = stack_frame[13];
        if((uint32_t)regs[RAX])
            return;
        if(copy_to_kernel(stack_frame[11]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(read_dbgregs_checked(old_dbgregs)
        || get_current_pcb_flags_ptr_checked(&p_pcb_flags)
        || get_pcb_dbregs_checked_at(p_pcb_flags, &pcb_flags_value, &had_dbgregs))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(set_pcb_dbregs_checked_at(p_pcb_flags, pcb_flags_value))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(write_dbgregs_checked(stack_frame+5))
        {
            restore_dbgregs_state_checked_at(p_pcb_flags, pcb_flags_value, old_dbgregs, had_dbgregs);
            regs[RAX] = EFAULT;
        }
    }
    else if(trap == 2)
    {
        uint64_t stack_frame[15];
        if(pop_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return;
        if((uint32_t)regs[RAX])
        {
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return;
            return;
        }
        uint32_t pid = stack_frame[5];
        uint32_t sysc_no = stack_frame[6];
        uint64_t proc_u;
        if(kpeek64_checked(stack_frame[13]+td_proc, &proc_u))
            goto fail_remote_syscall;
        int64_t proc = proc_u;
        while(proc < -0x100000000)
        {
            if(kpeek64_checked(proc+8, &proc_u))
                goto fail_remote_syscall;
            proc = proc_u;
        }
        while(proc)
        {
            uint64_t proc_pid;
            if(kpeek64_checked(proc+p_pid, &proc_pid))
                goto fail_remote_syscall;
            if((uint32_t)proc_pid == pid)
                break;
            if(kpeek64_checked(proc, &proc_u))
                goto fail_remote_syscall;
            proc = proc_u;
        }
        if(!proc)
        {
            regs[RAX] = ESRCH;
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return;
            return;
        }
        if(kpeek64_checked(proc+16, &regs[RDI]))
            goto fail_remote_syscall;
        uint64_t stack_frame_2[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 3), [6] = stack_frame[13], regs[RDI]};
        memcpy(stack_frame_2+8, stack_frame+7, 48);
        uint64_t sysc_target = 0;
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            stack_frame_2[1] = MKTRAP(TRAP_KEKCALL, 4);

            uint64_t thread_pcb;
            if(kpeek64_checked(regs[RDI] + td_pcb, &thread_pcb))
                goto fail_remote_syscall;
            if(kpeek64_checked(get_pcb_field_ptr(thread_pcb, pcb_fsbase), &stack_frame_2[8]))
                goto fail_remote_syscall;
            if(copy_to_kernel(stack_frame[13]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
                goto fail_remote_syscall;
        }
        else
        {
            if(kpeek64_checked((uint64_t)&sysents[sysc_no].sy_call, &sysc_target))
                goto fail_remote_syscall;
            if(copy_to_kernel(regs[RDI]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
                goto fail_remote_syscall;
        }
        if(push_stack_checked(regs, stack_frame_2, sizeof(stack_frame_2)))
            goto fail_remote_syscall;
        regs[RAX] = (uint64_t)&sysents[sysc_no];
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            regs[RIP] = (uint64_t)copyout;
            regs[RDI] = regs[RSP] + 64;
            regs[RSI] = stack_frame[8];
            regs[RDX] = 8;
        }
        else
        {
            regs[RIP] = sysc_target;
            regs[RSI] = regs[RSP] + 64;
            handle_syscall(regs, 0);
        }
        return;
fail_remote_syscall:
        regs[RAX] = EFAULT;
        if(pop_stack_checked(regs, &regs[RIP], 8))
            return;
        return;
    }
    else if(trap == 3 || trap == 4)
    {
        uint64_t stack_frame[14];
        if(pop_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return;
        if(trap == 3 && !(uint32_t)regs[RAX])
        {
            uint64_t retval;
            if(kpeek64_checked(stack_frame[6]+td_retval, &retval))
                regs[RAX] = EFAULT;
            else
                kpoke64(stack_frame[5]+td_retval, retval);
        }
        regs[RIP] = stack_frame[13];
    }
}
