#pragma once
#include <sys/types.h>
#include <sys/syscall.h>

void handle_fpkg_syscall(uint64_t* regs, int enable_ppr_plaintext_traps);
void handle_fpkg_trap(uint64_t* regs, uint32_t trapno);
int is_fpkg_trap_rip(uint64_t rip);
int try_handle_fpkg_trap(uint64_t* regs);
int try_handle_fpkg_mailbox(uint64_t* regs, uint64_t lr);
int control_ppr_plaintext_request(uint64_t magic, uint64_t mode,
                                  uint64_t arg0, uint64_t arg1,
                                  uint64_t arg2, uint64_t arg3,
                                  uint64_t* result);
