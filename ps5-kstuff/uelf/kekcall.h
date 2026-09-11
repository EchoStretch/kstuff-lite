#pragma once
#include <sys/types.h>

int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr);
void handle_kekcall_trap(uint64_t* regs, uint32_t trap);
