#include <errno.h>
#include <string.h>
#include "utils.h"
#include "log.h"
#include "npdrm.h"
#include "structs.h"
#include "traps.h"

static int copy_from_kernel_raw(void* dst, uint64_t src, uint64_t sz)
{
    char* p_dst = dst;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(src, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(p_dst, DMEM + phys, chk);
        p_dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

static int copy_to_kernel_raw(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM + phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

int virt2phys(uint64_t addr, uint64_t* phys, uint64_t* phys_limit)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(virt2phys_calls);
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12))) //dmem mapping size
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdead0000dead0000);
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdeaddeaddeaddead);
            log_word((uint64_t)__builtin_return_address(0));
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
    METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
    return 0;
}

int copy_from_kernel(void* dst, uint64_t src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    uint64_t total = sz;
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, total);
    if(!sz)
    {
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return 0;
    }
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sz)
    {
        memcpy(dst, DMEM + phys, sz);
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return 0;
    }
    if(copy_from_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    uint64_t total = sz;
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, total);
    if(!sz)
    {
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return 0;
    }
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sz)
    {
        memcpy(DMEM + phys, src, sz);
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return 0;
    }
    if(copy_to_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

int copy_u16_from_kernel(uint16_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_u32_from_kernel(uint32_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_u64_from_kernel(uint64_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_u16_to_kernel(uint64_t dst, uint16_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

int copy_u32_to_kernel(uint64_t dst, uint32_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

int copy_u64_to_kernel(uint64_t dst, uint64_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

uint64_t yield(void);

int run_gadget_checked(uint64_t* regs)
{
    if(copy_to_kernel(trap_frame, regs, NREGS*8))
        return EFAULT;
    uint64_t just_return = yield();
    uint64_t jr_frame[5];
    if(copy_from_kernel(regs, trap_frame, NREGS*8))
        return EFAULT;
    if(copy_from_kernel(jr_frame, just_return, 40))
        return EFAULT;
    regs[RDX] = jr_frame[2];
    regs[RCX] = jr_frame[3];
    regs[RAX] = jr_frame[4];
    return 0;
}

extern char dr2gpr_start[];
extern char gpr2dr_1_start[];
extern char gpr2dr_2_start[];
extern char rdmsr_start[];
extern char rdmsr_end[];
extern char wrmsr_ret[];
extern char mov_rax_cr0[];
extern char mov_cr0_rax[];
extern char doreti_iret[];
extern char syscall_after[];

int read_dbgregs_checked(uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)dr2gpr_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    if(run_gadget_checked(regs))
        return EFAULT;
    dr[0] = regs[R15];
    dr[1] = regs[R14];
    dr[2] = regs[R13];
    dr[3] = regs[R12];
    dr[4] = regs[R11];
    dr[5] = regs[RAX];
    return 0;
}

int write_dbgregs_checked(const uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)gpr2dr_1_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    regs[R15] = dr[0];
    regs[R14] = dr[1];
    regs[R13] = dr[2];
    regs[RBX] = dr[3];
    regs[R11] = dr[4];
    regs[RCX] = dr[5];
    regs[RAX] = dr[5];
    if(run_gadget_checked(regs))
        return EFAULT;
    regs[R11] = dr[4];
    regs[R15] = dr[5];
    regs[R12] = 0xdeadbeefdeadbeef;
    regs[RIP] = (uint64_t)gpr2dr_2_start;
    return run_gadget_checked(regs);
}

int rdmsr(uint32_t which, uint64_t* ans)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)rdmsr_start, 0x20, 0x102, 0, 0,
        [RCX] = which,
    };
    if(run_gadget_checked(regs))
        return 0;
    if(regs[RIP] == (uint64_t)rdmsr_start)
        return 0;
    *ans = regs[RDX] << 32 | (uint32_t)regs[RAX];
    return 1;
}

int wrmsr(uint32_t which, uint64_t value)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)wrmsr_ret, 0x20, 0x102, 0, 0,
        [RCX] = which,
        [RAX] = (uint32_t)value,
        [RDX] = value >> 32,
    };
    if(run_gadget_checked(regs))
        return 0;
    return regs[RIP] != (uint64_t)wrmsr_ret;
}

int read_cr0_checked(uint64_t* cr0)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)mov_rax_cr0, 0x20, 0x102, 0, 0,
    };
    if(run_gadget_checked(regs))
        return EFAULT;
    *cr0 = regs[RAX];
    return 0;
}

int write_cr0_checked(uint64_t cr0)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)mov_cr0_rax, 0x20, 0x102, 0, 0,
        [RAX] = cr0,
    };
    return run_gadget_checked(regs);
}

void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs)
{
    uint64_t stack_frame[12] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_UTILS, 1), 0, 0, 0, 0,
    };
    uint64_t p_pcb_flags;
    uint64_t pcb_flags_value;
    int had_dbregs;
    if(read_dbgregs_checked(stack_frame+6))
        return;
    if(get_current_pcb_flags_ptr_checked(&p_pcb_flags))
        return;
    if(get_pcb_dbregs_checked_at(p_pcb_flags, &pcb_flags_value, &had_dbregs))
        return;
    stack_frame[4] = had_dbregs;
    if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
        return;
    if(set_pcb_dbregs_checked_at(p_pcb_flags, pcb_flags_value))
        goto rollback_stack;
    if(write_dbgregs_checked(dbgregs))
    {
        restore_dbgregs_state_checked_at(p_pcb_flags, pcb_flags_value, stack_frame+6, had_dbregs);
rollback_stack:
        regs[RSP] += sizeof(stack_frame);
        return;
    }
}

void handle_utils_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        uint64_t stack_frame[12];
        if(peek_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return;
        if(restore_dbgregs_state_checked(stack_frame+5, stack_frame[4]))
            return;
        regs[RSP] += sizeof(stack_frame);
        regs[RIP] = stack_frame[11];
        finish_npdrm_ioctl_state();
        observe_current_syscall_finish();
    }
}
