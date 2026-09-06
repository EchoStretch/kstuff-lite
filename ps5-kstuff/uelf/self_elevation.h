#pragma once

#include <stdint.h>
#include "../../include/kstuff.h"

#define KSTUFF_SELF_ELEVATION_TRAP 5

int begin_elevate_current_process(uint64_t* regs, uint64_t thread,
                                  uint64_t magic, uint64_t version,
                                  uint64_t profile);
void finish_elevate_current_process(uint64_t* regs);
int inspect_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t selector, uint64_t* value);
