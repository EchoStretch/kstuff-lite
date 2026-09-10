#pragma once
#include <sys/types.h>

/* Runtime hook control uses kekcall number 8 (encoded in the upper 32 bits
 * of SYS_getppid). RDI is a kstuff_runtime_hook_command, RSI is a hook mask,
 * and the successful return value is the complete enabled-hook mask.
 * GET ignores RSI. All hooks are enabled by default. */
#define KEKCALL_RUNTIME_HOOK_CONTROL 8

enum kstuff_runtime_hook_command
{
    KSTUFF_RUNTIME_HOOK_GET = 0,
    KSTUFF_RUNTIME_HOOK_ENABLE,
    KSTUFF_RUNTIME_HOOK_DISABLE,
};

enum kstuff_runtime_hook_mask
{
    KSTUFF_RUNTIME_HOOK_NMOUNT = 1u << 0,
    KSTUFF_RUNTIME_HOOK_UNMOUNT = 1u << 1,
    KSTUFF_RUNTIME_HOOK_MPROTECT = 1u << 2,
    KSTUFF_RUNTIME_HOOK_MOUNT_UNMOUNT =
        KSTUFF_RUNTIME_HOOK_NMOUNT | KSTUFF_RUNTIME_HOOK_UNMOUNT,
    KSTUFF_RUNTIME_HOOK_ALL =
        KSTUFF_RUNTIME_HOOK_MOUNT_UNMOUNT | KSTUFF_RUNTIME_HOOK_MPROTECT,
};
int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr);
void handle_kekcall_trap(uint64_t* regs, uint32_t trap);
int runtime_syscall_hook_enabled(uint64_t hook);
