#include <errno.h>
#include <string.h>
#include "utils.h"
#include "log.h"
#include "npdrm.h"
#include "structs.h"
#include "traps.h"

static int copy_from_kernel_raw(void* dst, uint64_t src, uint64_t sz)
{
    char* p_dst = dst;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(src, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(p_dst, DMEM + phys, chk);
        p_dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

static int copy_to_kernel_raw(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM + phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

__attribute__((noinline)) int virt2phys(uint64_t addr, uint64_t* phys,
                                       uint64_t* phys_limit)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(virt2phys_calls);
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12))) //dmem mapping size
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdead0000dead0000);
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdeaddeaddeaddead);
            log_word((uint64_t)__builtin_return_address(0));
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
    METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
    return 0;
}

int copy_from_kernel(void* dst, uint64_t src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sz);
    if(copy_from_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sz);
    if(copy_to_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

#if KSTUFF_OBS
#define METRIC_SCALAR_COPY_FROM_TIME(start) do { \
    uint64_t _metric_elapsed = uelf_rdtsc() - (uint64_t)(start); \
    METRIC_INC(scalar_copy_from_calls); \
    METRIC_ADD(copy_from_cycles_total, _metric_elapsed); \
    METRIC_MAX(copy_from_cycles_max, _metric_elapsed); \
    METRIC_ADD(scalar_copy_from_cycles_total, _metric_elapsed); \
    METRIC_MAX(scalar_copy_from_cycles_max, _metric_elapsed); \
} while(0)

#define METRIC_SCALAR_COPY_TO_TIME(start) do { \
    uint64_t _metric_elapsed = uelf_rdtsc() - (uint64_t)(start); \
    METRIC_INC(scalar_copy_to_calls); \
    METRIC_ADD(copy_to_cycles_total, _metric_elapsed); \
    METRIC_MAX(copy_to_cycles_max, _metric_elapsed); \
    METRIC_ADD(scalar_copy_to_cycles_total, _metric_elapsed); \
    METRIC_MAX(scalar_copy_to_cycles_max, _metric_elapsed); \
} while(0)
#else
#define METRIC_SCALAR_COPY_FROM_TIME(start) do { } while(0)
#define METRIC_SCALAR_COPY_TO_TIME(start) do { } while(0)
#endif

int copy_u16_from_kernel(uint16_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u32_from_kernel(uint32_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u64_from_kernel(uint64_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u16_to_kernel(uint64_t dst, uint16_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

int copy_u32_to_kernel(uint64_t dst, uint32_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

int copy_u64_to_kernel(uint64_t dst, uint64_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

#undef METRIC_SCALAR_COPY_FROM_TIME
#undef METRIC_SCALAR_COPY_TO_TIME

uint64_t yield(void);

struct kernel_mapping_cache
{
    uint64_t physical_address[2];
    uint64_t first_segment_size;
    int valid;
#if KSTUFF_OBS
    uint64_t* hits;
    uint64_t* misses;
    uint64_t* fallbacks;
#endif
};

#if KSTUFF_OBS
#define DEFINE_MAPPING_CACHE(name, metric_prefix) \
    static struct kernel_mapping_cache name = { \
        .hits = &shared_area.metrics.metric_prefix##_hits, \
        .misses = &shared_area.metrics.metric_prefix##_misses, \
        .fallbacks = &shared_area.metrics.metric_prefix##_fallbacks, \
    }
#define OBSERVE_MAPPING_CACHE(cache, field) \
    __atomic_fetch_add((cache)->field, 1, __ATOMIC_RELAXED)
#else
#define DEFINE_MAPPING_CACHE(name, metric_prefix) \
    static struct kernel_mapping_cache name
#define OBSERVE_MAPPING_CACHE(cache, field) do { (void)(cache); } while(0)
#endif

DEFINE_MAPPING_CACHE(s_trap_frame_mapping, trap_mapping);
DEFINE_MAPPING_CACHE(s_just_return_mapping, just_return_mapping);
DEFINE_MAPPING_CACHE(s_pcpu_mapping, pcpu_mapping);
DEFINE_MAPPING_CACHE(s_tss_rsp0_mapping, tss_mapping);
DEFINE_MAPPING_CACHE(s_wrmsr_args_mapping, wrmsr_args_mapping);
DEFINE_MAPPING_CACHE(s_cr0_enter_hook_mapping, cr0_enter_hook_mapping);
DEFINE_MAPPING_CACHE(s_cr0_exit_hook_mapping, cr0_exit_hook_mapping);

#undef DEFINE_MAPPING_CACHE

extern char tss[];
extern uint64_t wrmsr_args;

/* These addresses belong to the per-CPU KELF and stay fixed for its lifetime. */
static __attribute__((noinline)) int initialize_kernel_mapping_cache(
    struct kernel_mapping_cache* cache, uint64_t address, uint64_t size)
{
    uint64_t physical_limit;
    uint64_t physical_address;
    if(!virt2phys(address, &physical_address, &physical_limit))
        return 0;
    if(physical_address >= physical_limit)
        return 0;

    uint64_t first_segment_size = physical_limit - physical_address;
    if(first_segment_size > size)
        first_segment_size = size;
    cache->physical_address[0] = physical_address;
    cache->first_segment_size = first_segment_size;

    if(first_segment_size < size)
    {
        uint64_t second_limit;
        if(!virt2phys(address + first_segment_size,
                      &cache->physical_address[1], &second_limit)
        || cache->physical_address[1] >= second_limit
        || size - first_segment_size
            > second_limit - cache->physical_address[1])
            return 0;
    }

    __atomic_store_n(&cache->valid, 1, __ATOMIC_RELEASE);
    return 1;
}

static int get_cached_kernel_mapping(struct kernel_mapping_cache* cache,
                                     uint64_t address, uint64_t size)
{
    if(__atomic_load_n(&cache->valid, __ATOMIC_ACQUIRE))
    {
        OBSERVE_MAPPING_CACHE(cache, hits);
        return 1;
    }
    OBSERVE_MAPPING_CACHE(cache, misses);
    int initialized = initialize_kernel_mapping_cache(cache, address, size);
    if(!initialized)
        OBSERVE_MAPPING_CACHE(cache, fallbacks);
    return initialized;
}

#undef OBSERVE_MAPPING_CACHE

static __attribute__((noinline, cold)) int copy_from_kernel_uncached(
    void* dst, uint64_t src, uint64_t size)
{
    return copy_from_kernel(dst, src, size);
}

static __attribute__((noinline, cold)) int copy_to_kernel_uncached(
    uint64_t dst, const void* src, uint64_t size)
{
    return copy_to_kernel(dst, src, size);
}

static void copy_from_kernel_mapping(const struct kernel_mapping_cache* cache,
                                     void* dst, uint64_t offset, uint64_t size)
{
    uint64_t first_size = 0;
    if(offset < cache->first_segment_size)
    {
        first_size = cache->first_segment_size - offset;
        if(first_size > size)
            first_size = size;
        memcpy(dst, DMEM + cache->physical_address[0] + offset, first_size);
    }
    if(first_size < size)
    {
        uint64_t second_offset = offset + first_size
                               - cache->first_segment_size;
        memcpy((char*)dst + first_size,
               DMEM + cache->physical_address[1] + second_offset,
               size - first_size);
    }
}

static void copy_to_kernel_mapping(const struct kernel_mapping_cache* cache,
                                   uint64_t offset, const void* src,
                                   uint64_t size)
{
    uint64_t first_size = 0;
    if(offset < cache->first_segment_size)
    {
        first_size = cache->first_segment_size - offset;
        if(first_size > size)
            first_size = size;
        memcpy(DMEM + cache->physical_address[0] + offset, src, first_size);
    }
    if(first_size < size)
    {
        uint64_t second_offset = offset + first_size
                               - cache->first_segment_size;
        memcpy(DMEM + cache->physical_address[1] + second_offset,
               (const char*)src + first_size, size - first_size);
    }
}

/*
 * The two continuation slots belong to the per-CPU KELF and do not move for
 * its lifetime.  Keep their tiny mappings separate: kernel_mapping_cache is
 * intentionally address-less after initialization and must only be used for
 * the exact address which initialized it.
 */
static __attribute__((noinline)) int copy_u64_to_fixed_kernel_mapping(
    struct kernel_mapping_cache* cache, uint64_t dst, uint64_t value)
{
    if(!get_cached_kernel_mapping(cache, dst, sizeof(value)))
        return copy_u64_to_kernel(dst, value);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    copy_to_kernel_mapping(cache, 0, &value, sizeof(value));
    return 0;
}

static __attribute__((noinline)) int copy_from_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, void* dst, uint64_t src,
    uint64_t mapping_size, uint64_t size)
{
    METRIC_TIME_START(start_cycles);
    if(size > mapping_size
    || !get_cached_kernel_mapping(cache, src, mapping_size))
        return copy_from_kernel_uncached(dst, src, size);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, size);
    copy_from_kernel_mapping(cache, dst, 0, size);
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

static __attribute__((noinline)) int copy_to_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, uint64_t dst, const void* src,
    uint64_t mapping_size, uint64_t size)
{
    METRIC_TIME_START(start_cycles);
    if(size > mapping_size
    || !get_cached_kernel_mapping(cache, dst, mapping_size))
        return copy_to_kernel_uncached(dst, src, size);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, size);
    copy_to_kernel_mapping(cache, 0, src, size);
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

static __attribute__((noinline)) int copy_u64_from_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, uint64_t src, uint64_t* value)
{
    METRIC_TIME_START(start_cycles);
    if(!get_cached_kernel_mapping(cache, src, sizeof(*value)))
        return copy_u64_from_kernel(value, src);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*value));
    copy_from_kernel_mapping(cache, value, 0, sizeof(*value));
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

enum {
    TRAP_FRAME_MAPPING_SIZE = trap_frame_extended_size,
    JUST_RETURN_MAPPING_SIZE = 5 * sizeof(uint64_t),
};

__attribute__((noinline)) int copy_from_trap_frame_cached(void* dst, size_t size)
{
    return copy_from_cached_kernel_mapping(&s_trap_frame_mapping, dst,
                                           trap_frame, TRAP_FRAME_MAPPING_SIZE,
                                           size);
}

__attribute__((noinline)) int copy_to_trap_frame_cached(const void* src, size_t size)
{
    return copy_to_cached_kernel_mapping(&s_trap_frame_mapping, trap_frame,
                                         src, TRAP_FRAME_MAPPING_SIZE, size);
}

static __attribute__((noinline)) int copy_from_trap_frame_offset_cached(
    void* dst, size_t offset, size_t size)
{
    if(offset > TRAP_FRAME_MAPPING_SIZE
    || size > TRAP_FRAME_MAPPING_SIZE - offset)
        return EFAULT;
    if(!get_cached_kernel_mapping(&s_trap_frame_mapping, trap_frame,
                                  TRAP_FRAME_MAPPING_SIZE))
        return copy_from_kernel_uncached(dst, trap_frame + offset, size);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, size);
    copy_from_kernel_mapping(&s_trap_frame_mapping, dst, offset, size);
    return 0;
}

static __attribute__((noinline)) int copy_to_trap_frame_offset_cached(
    size_t offset, const void* src, size_t size)
{
    if(offset > TRAP_FRAME_MAPPING_SIZE
    || size > TRAP_FRAME_MAPPING_SIZE - offset)
        return EFAULT;
    if(!get_cached_kernel_mapping(&s_trap_frame_mapping, trap_frame,
                                  TRAP_FRAME_MAPPING_SIZE))
        return copy_to_kernel_uncached(trap_frame + offset, src, size);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, size);
    copy_to_kernel_mapping(&s_trap_frame_mapping, offset, src, size);
    return 0;
}

__attribute__((noinline)) int copy_from_just_return_cached(void* dst,
                                                          uint64_t just_return,
                                                          size_t size)
{
    return copy_from_cached_kernel_mapping(&s_just_return_mapping, dst,
                                           just_return, JUST_RETURN_MAPPING_SIZE,
                                           size);
}

static __attribute__((noinline)) int copy_rax_from_just_return_cached(
    uint64_t* rax, uint64_t just_return)
{
    const size_t rax_offset = 4 * sizeof(uint64_t);
    METRIC_TIME_START(start_cycles);
    if(!get_cached_kernel_mapping(&s_just_return_mapping, just_return,
                                  JUST_RETURN_MAPPING_SIZE))
        return copy_u64_from_kernel(rax, just_return + rax_offset);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*rax));
    copy_from_kernel_mapping(&s_just_return_mapping, rax, rax_offset,
                             sizeof(*rax));
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

__attribute__((noinline)) int copy_current_thread_from_pcpu_cached(uint64_t* td)
{
    return copy_u64_from_cached_kernel_mapping(&s_pcpu_mapping,
                                               (uint64_t)pcpu, td);
}

__attribute__((noinline)) int copy_rsp0_from_tss_cached(uint64_t* rsp0)
{
    return copy_u64_from_cached_kernel_mapping(&s_tss_rsp0_mapping,
                                               (uint64_t)tss + 4, rsp0);
}

__attribute__((noinline)) int copy_to_wrmsr_args_cached(const uint64_t args[3])
{
    return copy_to_cached_kernel_mapping(&s_wrmsr_args_mapping, wrmsr_args,
                                         args, 3 * sizeof(*args),
                                         3 * sizeof(*args));
}

enum run_gadget_result
{
    RUN_GADGET_RESULT_NONE,
    RUN_GADGET_RESULT_RAX,
    RUN_GADGET_RESULT_FULL,
};

static __attribute__((noinline)) int run_gadget_result_checked(
    uint64_t* regs, enum run_gadget_result result, uint64_t* rax)
{
    METRIC_INC(run_gadget_calls);
    METRIC_TIME_START(start_cycles);
#define RETURN_RUN_GADGET(value) do { \
    int _run_gadget_result = (value); \
    if(_run_gadget_result) \
        METRIC_INC(run_gadget_failures); \
    METRIC_TIME(run_gadget_cycles_total, run_gadget_cycles_max, start_cycles); \
    return _run_gadget_result; \
} while(0)
    if(copy_to_trap_frame_cached(regs, NREGS*8))
        RETURN_RUN_GADGET(EFAULT);
    uint64_t just_return = yield();

    if(result == RUN_GADGET_RESULT_FULL)
    {
        if(copy_from_trap_frame_cached(regs, NREGS * sizeof(*regs)))
            RETURN_RUN_GADGET(EFAULT);
    }

    if(result != RUN_GADGET_RESULT_NONE)
    {
        if(result == RUN_GADGET_RESULT_RAX)
        {
            if(copy_rax_from_just_return_cached(rax, just_return))
                RETURN_RUN_GADGET(EFAULT);
        }
        else
        {
            uint64_t jr_frame[5];
            if(copy_from_just_return_cached(jr_frame, just_return,
                                            sizeof(jr_frame)))
                RETURN_RUN_GADGET(EFAULT);
            regs[RDX] = jr_frame[2];
            regs[RCX] = jr_frame[3];
            regs[RAX] = jr_frame[4];
        }
    }
    RETURN_RUN_GADGET(0);
#undef RETURN_RUN_GADGET
}

__attribute__((noinline)) int run_gadget_checked(uint64_t* regs)
{
    return run_gadget_result_checked(regs, RUN_GADGET_RESULT_FULL, NULL);
}

static int run_gadget_capture_rax_checked(uint64_t* regs, uint64_t* rax)
{
    return run_gadget_result_checked(regs, RUN_GADGET_RESULT_RAX, rax);
}

static int run_gadget_no_result_checked(uint64_t* regs)
{
    return run_gadget_result_checked(regs, RUN_GADGET_RESULT_NONE, NULL);
}

extern char dr2gpr_start[];
extern char cpu_switch[];
extern char rdmsr_start[];
extern char rdmsr_end[];
extern char wrmsr_ret[];
extern char mov_rax_cr0[];
extern char cr0_load[];
extern char cr0_clear_store[];
extern char cr0_write_ret[];
extern char store_rax_rdi[];
extern char pop_all_iret[];
extern char doreti_iret[];
extern char syscall_after[];

int read_dbgregs_checked(uint64_t* dr)
{
    METRIC_INC(dbg_read_calls);
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)dr2gpr_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    if(run_gadget_checked(regs))
        return EFAULT;
    dr[0] = regs[R15];
    dr[1] = regs[R14];
    dr[2] = regs[R13];
    dr[3] = regs[R12];
    dr[4] = regs[R11];
    dr[5] = regs[RAX];
    return 0;
}

int write_dbgregs_checked(const uint64_t* dr)
{
    enum
    {
        CPU_SWITCH_DR0 = 0x78 / sizeof(uint64_t),
        CPU_SWITCH_DR1 = 0x80 / sizeof(uint64_t),
        CPU_SWITCH_DR2 = 0x88 / sizeof(uint64_t),
        CPU_SWITCH_DR3 = 0x90 / sizeof(uint64_t),
        CPU_SWITCH_DR6 = 0x98 / sizeof(uint64_t),
        CPU_SWITCH_DR7 = 0xa0 / sizeof(uint64_t),
        CPU_SWITCH_RETURN_SLOT = 0xa8 / sizeof(uint64_t),
    };
    _Static_assert(CPU_SWITCH_RETURN_SLOT < RIP,
                   "cpu_switch scratch overlaps the iret frame");

    METRIC_INC(dbg_write_calls);
    METRIC_INC(dbg_write_chain_calls);
    METRIC_INC(dbg_write_elided_gadgets);

    /*
     * This is the common cpu_switch tail which restores all six debug
     * registers from pcb offsets 0x78..0xa0.  2.50 has the older function
     * layout; every supported 3.00+ offset table has the newer layout.  13.60
     * was verified separately: cpu_switch+0x874 starts at the DR0 load and
     * reaches the zero-return tail without another firmware-specific delta.
     *
     * TODO(FW_PORT): for a new firmware, disassemble offsets.cpu_switch and
     * find the tail which loads DR0/DR1/DR2/DR3/DR6/DR7 from the PCB, follows
     * the expected register/stack epilogue, and ends with xor eax,eax.  Add an
     * explicit firmware delta if it is not +0x874; RAX=0 is the completion
     * marker and must remain true at the selected return.
     */
    const uint64_t tail_delta = FWVER <= 0x270 ? 0x704 : 0x874;
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)cpu_switch + tail_delta,
        [CS] = 0x20,
        [EFLAGS] = 2,
        [RAX] = 0xdeadbeefdeadbeef,
    };
    regs[RDI] = trap_frame;
    regs[R9] = trap_frame + CPU_SWITCH_RETURN_SLOT * sizeof(uint64_t);
    regs[RBX] = 0xdeadbeefdeadbeef;
    regs[CPU_SWITCH_DR0] = dr[0];
    regs[CPU_SWITCH_DR1] = dr[1];
    regs[CPU_SWITCH_DR2] = dr[2];
    regs[CPU_SWITCH_DR3] = dr[3];
    regs[CPU_SWITCH_DR6] = dr[4];
    regs[CPU_SWITCH_DR7] = dr[5];

    /* The verified tail ends with xor eax, eax.  Poison the input above and
     * accept only that zero as proof that the complete tail executed. */
    uint64_t completion;
    if(run_gadget_capture_rax_checked(regs, &completion))
        return EFAULT;
    if(completion)
    {
        METRIC_INC(run_gadget_failures);
        return EFAULT;
    }
    return 0;
}

__attribute__((noinline))
int snapshot_current_dbgregs_checked(struct dbgregs_snapshot* snapshot)
{
    if(get_current_pcb_flags_ptr_checked(&snapshot->p_pcb_flags))
        return 1;
    if(get_pcb_dbregs_checked_at(snapshot->p_pcb_flags,
                                 &snapshot->flags_value,
                                 &snapshot->had_dbregs))
        return 1;

    if(snapshot->had_dbregs)
    {
        METRIC_INC(dbg_snapshot_reads);
        return read_dbgregs_checked(snapshot->dr);
    }

    /*
     * PCB_DBREGS clear means the hardware debug registers do not belong to
     * this thread.  Match FreeBSD reset_dbregs(): restore an all-zero,
     * disabled state without paying for a kernel transition to snapshot
     * stale registers.
     */
    memset(snapshot->dr, 0, sizeof(snapshot->dr));
    METRIC_INC(dbg_snapshot_skips);
    return 0;
}

__attribute__((noinline))
int install_dbgregs_checked(const uint64_t* dr,
                            const struct dbgregs_snapshot* snapshot)
{
    if(!snapshot->had_dbregs
    && set_pcb_dbregs_checked_at(snapshot->p_pcb_flags,
                                 snapshot->flags_value))
        return 1;
    if(!write_dbgregs_checked(dr))
        return 0;

    restore_dbgregs_state_checked_at(snapshot->p_pcb_flags,
                                     snapshot->flags_value,
                                     snapshot->dr,
                                     snapshot->had_dbregs);
    return 1;
}

int rdmsr(uint32_t which, uint64_t* ans)
{
    METRIC_INC(msr_read_calls);
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)rdmsr_start, 0x20, 0x102, 0, 0,
        [RCX] = which,
    };
    if(run_gadget_checked(regs))
        return 0;
    if(regs[RIP] == (uint64_t)rdmsr_start)
        return 0;
    *ans = regs[RDX] << 32 | (uint32_t)regs[RAX];
    return 1;
}

int wrmsr(uint32_t which, uint64_t value)
{
    METRIC_INC(msr_write_calls);
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)wrmsr_ret, 0x20, 0x102, 0, 0,
        [RCX] = which,
        [RAX] = (uint32_t)value,
        [RDX] = value >> 32,
    };
    if(run_gadget_checked(regs))
        return 0;
    return regs[RIP] != (uint64_t)wrmsr_ret;
}

static int is_sane_cr0(uint64_t cr0)
{
    const uint64_t known_bits = 0xe005003f;
    const uint64_t required_bits = 0x80000001;
    return !(cr0 & ~known_bits)
        && (cr0 & required_bits) == required_bits;
}

static int cr0_chain_available(void)
{
    return (uint64_t)cr0_load > 0x1000
        && (uint64_t)cr0_clear_store > 0x1000
        && (uint64_t)store_rax_rdi > 0x1000;
}

static int read_cr0_checked(uint64_t* cr0)
{
    METRIC_INC(cr0_read_calls);
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)mov_rax_cr0, 0x20, 0x102, 0, 0,
    };
    return run_gadget_capture_rax_checked(regs, cr0) ? EFAULT : 0;
}

static int read_cr0_clear_ts_legacy_checked(uint64_t* cr0)
{
    if(read_cr0_checked(cr0))
        return EFAULT;
    if(!is_sane_cr0(*cr0))
        return EFAULT;
    if(!(*cr0 & 8))
    {
        METRIC_INC(cr0_ts_already_clear);
        METRIC_INC(cr0_clear_elided_transitions);
        return 0;
    }
    return write_cr0_checked(*cr0 & ~8ull);
}

static uint64_t cr0_enter_hook_address;
static uint64_t cr0_exit_hook_address;

static int write_cr0_hook_cached(struct kernel_mapping_cache* mapping,
                                 uint64_t* cached_address,
                                 size_t trap_frame_offset, uint64_t value)
{
    uint64_t hook = *cached_address;
    if(!hook)
    {
        if(copy_from_trap_frame_offset_cached(&hook, trap_frame_offset,
                                              sizeof(hook))
        || (hook >> 48) != 0xffff)
            return EFAULT;
        *cached_address = hook;
    }
    return copy_u64_to_fixed_kernel_mapping(mapping, hook, value);
}

static int arm_cr0_fast_enter(void)
{
    METRIC_TIME_START(start_cycles);
    uint64_t enter_stack = trap_frame + fpu_cr0_fast_enter_stack_offset;
    if(write_cr0_hook_cached(&s_cr0_enter_hook_mapping,
                             &cr0_enter_hook_address,
                             fpu_cr0_enter_hook_ptr_offset, enter_stack))
    {
        METRIC_INC(cr0_fast_enter_failures);
        METRIC_TIME(cr0_fast_enter_arm_cycles_total,
                    cr0_fast_enter_arm_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_INC(cr0_fast_enter_arms);
    METRIC_TIME(cr0_fast_enter_arm_cycles_total,
                cr0_fast_enter_arm_cycles_max, start_cycles);
    return 0;
}

static int read_cr0_clear_ts_chain_checked(uint64_t* cr0)
{
    struct cr0_chain_result
    {
        uint64_t committed;
        uint64_t cleared;
        uint64_t unused[9];
        uint64_t saved;
    } result;
    _Static_assert(sizeof(result) == 0x60, "unexpected CR0 result layout");

    METRIC_INC(cr0_chain_read_clear_calls);
    memset(&result, 0xff, sizeof(result));
    if(copy_to_trap_frame_offset_cached(fpu_cr0_scratch_offset, &result,
                                        sizeof(result)))
    {
        METRIC_INC(cr0_chain_failures);
        return EFAULT;
    }

    METRIC_INC(cr0_read_calls);
    if(arm_cr0_fast_enter())
    {
        METRIC_INC(cr0_chain_failures);
        return EFAULT;
    }
    (void)yield();

    if(copy_from_trap_frame_offset_cached(&result, fpu_cr0_scratch_offset,
                                          sizeof(result))
    || !is_sane_cr0(result.saved)
    || !is_sane_cr0(result.cleared)
    || result.cleared != (result.saved & ~8ull)
    || result.committed != result.cleared)
    {
        /* If the chain cleared an originally set TS, restore it before exit. */
        if(is_sane_cr0(result.saved) && (result.saved & 8))
            (void)write_cr0_checked(result.saved);
        METRIC_INC(cr0_chain_failures);
        return EFAULT;
    }

    *cr0 = result.saved;
    if(!(result.saved & 8))
        METRIC_INC(cr0_ts_already_clear);
    METRIC_INC(cr0_clear_elided_transitions);
    return 0;
}

int read_cr0_clear_ts_checked(uint64_t* cr0)
{
    METRIC_INC(cr0_read_clear_calls);
    METRIC_TIME_START(start_cycles);
#define RETURN_CR0_READ_CLEAR(value) do { \
    int _result = (value); \
    METRIC_TIME(cr0_read_clear_cycles_total, cr0_read_clear_cycles_max, \
                start_cycles); \
    return _result; \
} while(0)
    if(cr0_chain_available())
        RETURN_CR0_READ_CLEAR(read_cr0_clear_ts_chain_checked(cr0));
    RETURN_CR0_READ_CLEAR(read_cr0_clear_ts_legacy_checked(cr0));
#undef RETURN_CR0_READ_CLEAR
}

int write_cr0_checked(uint64_t cr0)
{
    METRIC_INC(cr0_write_calls);
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)cr0_write_ret, 0x20, 0x102, 0, 0,
        [RAX] = cr0,
    };
    return run_gadget_no_result_checked(regs);
}

static int write_cr0_preserving_trap_frame_checked(uint64_t cr0)
{
    uint64_t outer_regs[NREGS];
    if(copy_from_trap_frame_cached(outer_regs, sizeof(outer_regs)))
        return EFAULT;
    int result = write_cr0_checked(cr0);
    if(copy_to_trap_frame_cached(outer_regs, sizeof(outer_regs)))
        return EFAULT;
    return result;
}

int defer_cr0_restore_checked(uint64_t cr0)
{
    METRIC_INC(cr0_restore_calls);
    METRIC_TIME_START(start_cycles);
#define RETURN_CR0_RESTORE(value) do { \
    int _result = (value); \
    METRIC_TIME(cr0_restore_cycles_total, cr0_restore_cycles_max, \
                start_cycles); \
    return _result; \
} while(0)
    if(!cr0_chain_available())
        RETURN_CR0_RESTORE(write_cr0_preserving_trap_frame_checked(cr0));
    METRIC_TIME_START(arm_start_cycles);
    uint64_t restore_stack = trap_frame + fpu_cr0_exit_stack_offset;
    if(copy_to_trap_frame_offset_cached(fpu_cr0_deferred_offset, &cr0,
                                        sizeof(cr0))
    || write_cr0_hook_cached(&s_cr0_exit_hook_mapping,
                             &cr0_exit_hook_address,
                             fpu_cr0_exit_hook_ptr_offset,
                             restore_stack))
    {
        METRIC_TIME(cr0_deferred_arm_cycles_total,
                    cr0_deferred_arm_cycles_max, arm_start_cycles);
        RETURN_CR0_RESTORE(EFAULT);
    }
    METRIC_INC(cr0_deferred_restore_arms);
    METRIC_TIME(cr0_deferred_arm_cycles_total,
                cr0_deferred_arm_cycles_max, arm_start_cycles);
    RETURN_CR0_RESTORE(0);
#undef RETURN_CR0_RESTORE
}

void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs)
{
    uint64_t stack_frame[12] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_UTILS, 1), 0, 0, 0, 0,
    };
    struct dbgregs_snapshot snapshot;
    if(snapshot_current_dbgregs_checked(&snapshot))
        return;
    stack_frame[4] = snapshot.had_dbregs;
    memcpy(stack_frame + 6, snapshot.dr, sizeof(snapshot.dr));
    if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
        return;
    if(install_dbgregs_checked(dbgregs, &snapshot))
    {
        regs[RSP] += sizeof(stack_frame);
        return;
    }
}

void handle_utils_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        enum { FRAME_QWORDS = 12, TAIL_OFFSET_QWORDS = 3 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        if(peek_stack_tail_checked(regs, tail,
                                   FRAME_QWORDS * sizeof(uint64_t),
                                   TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                   sizeof(tail)))
            return;
        if(restore_dbgregs_state_checked(tail+2, tail[0]))
            return;
        regs[RSP] += FRAME_QWORDS * sizeof(uint64_t);
        regs[RIP] = tail[8];
        finish_npdrm_ioctl_state();
        observe_current_syscall_finish();
    }
}
