#pragma once

#include <stdint.h>

#define KSTUFF_SELF_ELEVATION_OP 7u
#define KSTUFF_SELF_ELEVATION_MAGIC UINT64_C(0x31564c4553355350)
#define KSTUFF_SELF_ELEVATION_ABI_VERSION UINT64_C(1)
#define KSTUFF_SELF_ELEVATION_PROFILE_DATA_ACCESS UINT64_C(1)

int elevate_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t profile);
