#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <machine/sysarch.h>
#include <string.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"
#include "log.h"
#include "fpkg.h"

extern char syscall_after[];
extern char doreti_iret[];
extern char nop_ret[];
extern char copyout[];
extern char copyin[];
extern struct sysent sysents[];

static uint64_t runtime_syscall_hook_status(void)
{
    uint64_t disabled = __atomic_load_n(
        &shared_area.runtime_syscall_hook_disable_mask, __ATOMIC_ACQUIRE);
    return KSTUFF_RUNTIME_HOOK_ALL & ~disabled;
}

int runtime_syscall_hook_enabled(uint64_t hook)
{
    return (runtime_syscall_hook_status() & hook) == hook;
}

static int control_runtime_syscall_hooks(uint64_t command, uint64_t mask,
                                         uint64_t* result)
{
    if(command == KSTUFF_RUNTIME_HOOK_GET)
    {
        *result = runtime_syscall_hook_status();
        return 0;
    }
    if(!mask || (mask & ~KSTUFF_RUNTIME_HOOK_ALL))
        return EINVAL;

    if(command == KSTUFF_RUNTIME_HOOK_ENABLE)
    {
        __atomic_fetch_and(&shared_area.runtime_syscall_hook_disable_mask,
                           ~mask, __ATOMIC_ACQ_REL);
    }
    else if(command == KSTUFF_RUNTIME_HOOK_DISABLE)
    {
        __atomic_fetch_or(&shared_area.runtime_syscall_hook_disable_mask,
                          mask, __ATOMIC_ACQ_REL);
    }
    else
        return EINVAL;

    *result = runtime_syscall_hook_status();
    return 0;
}

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
    else if(nr == 7)
    {
        uint64_t result = 0;
        int err = control_ppr_plaintext_request(args[RDI], args[RSI],
                                                args[RDX], 0,
                                                args[R8], args[R9],
                                                &result);
        if(!err)
            args[RAX] = result;
        return err;
    }
    else if(nr == KEKCALL_RUNTIME_HOOK_CONTROL)
    {
        uint64_t result = 0;
        int err = control_runtime_syscall_hooks(args[RDI], args[RSI],
                                                &result);
        if(!err)
            args[RAX] = result;
        return err;
    }
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
        enum { FRAME_QWORDS = 14, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        struct dbgregs_snapshot snapshot;
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        regs[RIP] = tail[8];
        if((uint32_t)regs[RAX])
            return;
        if(copy_to_kernel(tail[6]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(snapshot_current_dbgregs_checked(&snapshot))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(install_dbgregs_checked(tail, &snapshot))
        {
            regs[RAX] = EFAULT;
        }
    }
    else if(trap == 2)
    {
        enum { FRAME_QWORDS = 15, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[9];
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        if((uint32_t)regs[RAX])
        {
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return;
            return;
        }
        uint32_t pid = tail[0];
        uint32_t sysc_no = tail[1];
        uint64_t proc_u;
        if(kpeek64_checked(tail[8]+td_proc, &proc_u))
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
        uint64_t stack_frame_2[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 3), [6] = tail[8], regs[RDI]};
        memcpy(stack_frame_2+8, tail+2, 48);
        uint64_t sysc_target = 0;
        if(sysc_no == SYS_sysarch && (uint32_t)tail[2] == AMD64_GET_FSBASE)
        {
            stack_frame_2[1] = MKTRAP(TRAP_KEKCALL, 4);

            uint64_t thread_pcb;
            if(kpeek64_checked(regs[RDI] + td_pcb, &thread_pcb))
                goto fail_remote_syscall;
            if(kpeek64_checked(get_pcb_field_ptr(thread_pcb, pcb_fsbase), &stack_frame_2[8]))
                goto fail_remote_syscall;
            if(copy_to_kernel(tail[8]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
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
        if(sysc_no == SYS_sysarch && (uint32_t)tail[2] == AMD64_GET_FSBASE)
        {
            regs[RIP] = (uint64_t)copyout;
            regs[RDI] = regs[RSP] + 64;
            regs[RSI] = tail[3];
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
        enum { FRAME_QWORDS = 14, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        if(trap == 3 && !(uint32_t)regs[RAX])
        {
            uint64_t retval;
            if(kpeek64_checked(tail[1]+td_retval, &retval))
                regs[RAX] = EFAULT;
            else
                kpoke64(tail[0]+td_retval, retval);
        }
        regs[RIP] = tail[8];
    }
}
