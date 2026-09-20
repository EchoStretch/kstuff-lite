#include <string.h>
#include "utils.h"
#include "syscall_fixes.h"

extern char mprotect_fix_start[];
extern char mprotect_fix_end[];

static uint64_t dbgregs_for_syscall_fix[6] = {
    (uint64_t)mprotect_fix_start, (uint64_t)aslr_fix_start, 0, 0,
    0, 0x405,
};

/* application_on_exec_switched_vmspace copies appinfo bit 0x100 to vm_map
 * bit 0x4.  Wire /app0/eboot.bin before the execve hooks are removed. */
static void fix_app_wire_flag(uint64_t* regs)
{
    uint64_t fw = FWVER;
    if(fw < 0x100 || fw > 0x1360)
        return;

    /* Derived from application_on_exec_switched_vmspace and _exec_self_imgact. */
    uint64_t proc_appinfo_offset = fw < 0x300 ? 0x500 :
                                   fw < 0x600 ? 0x538 :
                                   fw < 0x700 ? 0x560 :
                                   fw < 0x1000 ? 0x568 :
                                   fw < 0x1200 ? 0x570 : 0x578;
    uint64_t wire_flag_offset = fw < 0x105 ? 0xf4 :
                                fw < 0x200 ? 0xfc :
                                fw < 0x700 ? 0x108 :
                                fw < 0x800 ? 0x118 :
                                fw < 0x900 ? 0x120 : 0x140;

    uint64_t td, proc, imgp, imgp_proc, path_ptr, appinfo;
    uint16_t flags;
    char path[sizeof("/app0/eboot.bin")];
    if(fw < 0x300)
    {
        if(copy_u64_from_kernel(&imgp, regs[RBP] - 0x58))
            return;
    }
    else
        imgp = fw < 0x600 ? regs[R15] :
               fw < 0x700 ? regs[R13] :
               fw < 0x800 ? regs[R14] : regs[RBX];

    if(!imgp)
        return;
    if(copy_current_thread_from_pcpu_cached(&td) || !td
    || copy_u64_from_kernel(&proc, td + td_proc) || !proc
    || copy_u64_from_kernel(&imgp_proc, imgp) || imgp_proc != proc
    || copy_u64_from_kernel(&path_ptr, imgp + 0x78) || !path_ptr
    || copy_from_kernel(path, path_ptr, sizeof(path))
    || memcmp(path, "/app0/eboot.bin", sizeof(path)))
        return;

    if(copy_u64_from_kernel(&appinfo, proc + proc_appinfo_offset) || !appinfo
    || copy_u16_from_kernel(&flags, appinfo + wire_flag_offset))
        return;
    if(!(flags & 0x100))
        (void)copy_u16_to_kernel(appinfo + wire_flag_offset, flags | 0x100);
}

void handle_syscall_fix(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_syscall_fix);
}

int try_handle_syscall_fix_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)mprotect_fix_start)
        regs[RIP] = (uint64_t)mprotect_fix_end;
    else if (regs[RIP] == (uint64_t) aslr_fix_start)
    {
        fix_app_wire_flag(regs);
        regs[RIP] = (uint64_t) aslr_fix_end;
    }
    else
        return 0;
    return 1;
}
