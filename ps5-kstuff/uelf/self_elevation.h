#pragma once

#include <stdint.h>
#include "../../include/kstuff.h"

int elevate_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t profile);
int inspect_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t selector, uint64_t* value);
