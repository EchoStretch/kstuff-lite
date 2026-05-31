#include <sys/types.h>
#include "mailbox.h"
#include "utils.h"
#include "log.h"
#include "fself.h"
#include "fpkg.h"
#include "npdrm.h"

extern char sceSblServiceMailbox[];

int try_handle_mailbox_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblServiceMailbox)
    {
        METRIC_INC(mailbox_traps);
        uint64_t lr = kpeek64(regs[RSP]);
        int fself_result = try_handle_fself_mailbox(regs, lr);
        if(fself_result & FSELF_HANDLE_HANDLED)
        {
            METRIC_INC(mailbox_fself);
            observe_current_syscall_trap();
            if(fself_result & FSELF_HANDLE_EMULATED)
                observe_current_syscall_emulated();
            return 1;
        }
        if(try_handle_fpkg_mailbox(regs, lr))
        {
            METRIC_INC(mailbox_fpkg);
            observe_current_syscall_trap();
            return 1;
        }
        if(try_handle_npdrm_mailbox(regs, lr))
        {
            METRIC_INC(mailbox_npdrm);
            observe_current_syscall_trap();
            return 1;
        }
        METRIC_INC(mailbox_unhandled);
    }
    else
        return 0;
    return 1;
}
