#include "r0gdb.h"
#include "offsets.h"

struct offset_table offsets;
extern uint64_t kdata_base;

#define KDATA_OFFSET(x) offsets.x = kdata_base + x;
#define ABSOLUTE_OFFSET(x) offsets.x = x;
#define OPTIONAL_KDATA_OFFSET(x) offsets.x = x ? kdata_base + x : 0;
#define DEF(x, y) enum { x = (y) + 0 * sizeof(offsets.x) };

#define START_FW(fw) void set_offsets_ ## fw(void) {
#define END_FW() }

/*
 * Keep incomplete tables explicit and reject them in set_offsets().  These
 * zero deltas are unsupported sentinels, never runtime fallback addresses.
 *
 * A zero delta resolves to kdata_base and is rejected before UELF starts.
 */
#define UNSUPPORTED_CR0_CHAIN_OFFSETS() \
    DEF(cr0_load, 0) \
    DEF(cr0_clear_store, 0) \
    DEF(cr0_write_ret, 0) \
    DEF(store_rax_rdi, 0)

/*
 * TODO(FW_PORT): add offsets/<major>_<minor>.h here for every new firmware.
 * Start from the nearest table only as a list of symbols; every address must
 * be re-derived from that firmware's executable kernel image and expressed
 * relative to the same kdata anchor passed by elfldr.
 */
#include "offsets/2_30.h"
#include "offsets/2_50.h"
#include "offsets/2_70.h"
#include "offsets/3_00.h"
#include "offsets/3_10.h"
#include "offsets/3_20.h"
#include "offsets/3_21.h"
#include "offsets/4_00.h"
#include "offsets/4_02.h"
#include "offsets/4_03.h"
#include "offsets/4_50.h"
#include "offsets/4_51.h"
#include "offsets/5_00.h"
#include "offsets/5_02.h"
#include "offsets/5_10.h"
#include "offsets/5_50.h"
#include "offsets/6_00.h"
#include "offsets/6_02.h"
#include "offsets/6_50.h"
#include "offsets/7_00.h"
#include "offsets/7_01.h"
#include "offsets/7_20.h"
#include "offsets/7_40.h"
#include "offsets/7_60.h"
#include "offsets/7_61.h"
#include "offsets/8_00.h"
#include "offsets/8_20.h"
#include "offsets/8_40.h"
#include "offsets/8_60.h"
#include "offsets/9_00.h"
#include "offsets/9_05.h"
#include "offsets/9_20.h"
#include "offsets/9_40.h"
#include "offsets/9_60.h"
#include "offsets/10_00.h"
#include "offsets/10_01.h"
#include "offsets/10_20.h"
#include "offsets/10_40.h"
#include "offsets/10_60.h"
#include "offsets/11_00.h"
#include "offsets/11_20.h"
#include "offsets/11_40.h"
#include "offsets/11_60.h"
#include "offsets/12_00.h"
#include "offsets/12_02.h"
#include "offsets/12_20.h"
#include "offsets/12_40.h"
#include "offsets/12_60.h"
#include "offsets/12_70.h"

#undef UNSUPPORTED_CR0_CHAIN_OFFSETS

void* dlsym(void*, const char*);

int set_offsets(void)
{
    uint32_t ver = r0gdb_get_fw_version() >> 16;
    switch(ver)
    {
#ifndef NO_BUILTIN_OFFSETS
    /* TODO(FW_PORT): register the new set_offsets_<fw>() table here too. */
    case 0x230: set_offsets_230(); break;
    case 0x250: set_offsets_250(); break;
    case 0x270: set_offsets_270(); break;
    case 0x300: set_offsets_300(); break;
    case 0x310: set_offsets_310(); break;
    case 0x320: set_offsets_320(); break;
    case 0x321: set_offsets_321(); break;
    case 0x400: set_offsets_400(); break;
    case 0x402: set_offsets_402(); break;
    case 0x403: set_offsets_403(); break;
    case 0x450: set_offsets_450(); break;
    case 0x451: set_offsets_451(); break;
    case 0x500: set_offsets_500(); break;
    case 0x502: set_offsets_502(); break;
    case 0x510: set_offsets_510(); break;
    case 0x550: set_offsets_550(); break;
    case 0x600: set_offsets_600(); break;
    case 0x602: set_offsets_602(); break;
    case 0x650: set_offsets_650(); break;
    case 0x700: set_offsets_700(); break;
    case 0x701: set_offsets_701(); break;
    case 0x720: set_offsets_720(); break;
    case 0x740: set_offsets_740(); break;
    case 0x760: set_offsets_760(); break;
    case 0x761: set_offsets_761(); break;
    case 0x800: set_offsets_800(); break;
    case 0x820: set_offsets_820(); break;
    case 0x840: set_offsets_840(); break;
    case 0x860: set_offsets_860(); break;
    case 0x900: set_offsets_900(); break;
    case 0x905: set_offsets_905(); break;
    case 0x920: set_offsets_920(); break;
    case 0x940: set_offsets_940(); break;
    case 0x960: set_offsets_960(); break;
    case 0x1000: set_offsets_1000(); break;
    case 0x1001: set_offsets_1001(); break;
    case 0x1020: set_offsets_1020(); break;
    case 0x1040: set_offsets_1040(); break;
    case 0x1060: set_offsets_1060(); break;
    case 0x1100: set_offsets_1100(); break;
    case 0x1120: set_offsets_1120(); break;
    case 0x1140: set_offsets_1140(); break;
    case 0x1160: set_offsets_1160(); break;
    case 0x1200: set_offsets_1200(); break;
    case 0x1202: set_offsets_1202(); break;
    case 0x1220: set_offsets_1220(); break;
    case 0x1240: set_offsets_1240(); break;
    case 0x1260: set_offsets_1260(); break;
    case 0x1270: set_offsets_1270(); break;
	
#endif
    default: return -1;
    }

    /* Reject any table containing an unsupported zero-delta sentinel. */
#undef KDATA_OFFSET
#undef ABSOLUTE_OFFSET
#undef OPTIONAL_KDATA_OFFSET
#define KDATA_OFFSET(x) if(offsets.x == kdata_base) return -1;
#define ABSOLUTE_OFFSET(x) if(!offsets.x) return -1;
#define OPTIONAL_KDATA_OFFSET(x)
#include "offsets/offset_list.txt"
#undef KDATA_OFFSET
#undef ABSOLUTE_OFFSET
#undef OPTIONAL_KDATA_OFFSET

    return 0;
}
