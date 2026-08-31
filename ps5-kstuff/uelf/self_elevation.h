#pragma once

#include <stdint.h>

#define KSTUFF_SELF_ELEVATION_OP 7u
#define KSTUFF_SELF_INSPECTION_OP 8u
#define KSTUFF_SELF_ELEVATION_MAGIC UINT64_C(0x31564c4553355350)
#define KSTUFF_SELF_ELEVATION_ABI_VERSION UINT64_C(1)
#define KSTUFF_SELF_ELEVATION_PROFILE_DATA_ACCESS UINT64_C(1)
#define KSTUFF_SELF_ELEVATION_PROFILE_PROCESS_MEMORY UINT64_C(2)
#define KSTUFF_SELF_ELEVATION_PROFILE_DEBUG UINT64_C(3)
#define KSTUFF_SELF_INSPECTION_AUTH_ID UINT64_C(1)

int elevate_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t profile);
int inspect_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t selector, uint64_t* value);
