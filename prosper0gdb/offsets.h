#pragma once
#include <stdint.h>

struct offset_table
{
#define KDATA_OFFSET(x) uint64_t x;
#define ABSOLUTE_OFFSET(x) int64_t x;
#define OPTIONAL_KDATA_OFFSET(x) uint64_t x;
#include "offsets/offset_list.txt"
#undef KDATA_OFFSET
#undef ABSOLUTE_OFFSET
#undef OPTIONAL_KDATA_OFFSET
};

extern struct offset_table offsets;
