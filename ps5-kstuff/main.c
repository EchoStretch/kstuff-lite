#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"
#include "uelf/structs.h"
#include "uelf/shared_area.h"

void* dlsym(void*, const char*);
void* memcpy(void * __restrict, const void * __restrict, size_t);
int (*snprintf)(char * restrict str, size_t size, const char * restrict format, ...);

void notify(const char* s)
{
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while(*d++ = *s++);
    int fd = open("/dev/notification0", 1);
    write(fd, &notification, 0xc30);
    close(fd);
}

void die(int line)
{
    char buf[64] = "problem encountered on main.c line ";
    char* p = buf;
    while(*p)
        p++;
    int q = 1;
    while(line / 10 > q)
        q *= 10;
    while(q)
    {
        *p++ = '0' + (line / q) % 10;
        q /= 10;
    }
    notify(buf);
    r0gdb_cleanup();
    asm volatile("ud2");
}

#define die() die(__LINE__)

extern uint64_t kdata_base;

void kmemcpy(void* dst, const void* src, size_t sz);

static void kpoke64(void* dst, uint64_t src)
{
    kmemcpy(dst, &src, 8);
}

enum { KZERO_CHUNK_SIZE = 1 << 16 };

static void* get_zero_chunk(void)
{
    static char* zero_chunk;
    if(!zero_chunk)
    {
        zero_chunk = mmap(0, KZERO_CHUNK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if(zero_chunk == MAP_FAILED)
            die();
        if(mlock(zero_chunk, KZERO_CHUNK_SIZE))
            die();
    }
    return zero_chunk;
}

static void kmemzero(void* dst, size_t sz)
{
    const char* zero_chunk = get_zero_chunk();
    while(sz)
    {
        size_t chunk = sz;
        if(chunk > KZERO_CHUNK_SIZE)
            chunk = KZERO_CHUNK_SIZE;
        kmemcpy(dst, zero_chunk, chunk);
        dst = (char*)dst + chunk;
        sz -= chunk;
    }
}

static int strcmp(const char* a, const char* b)
{
    while(*a && *a == *b)
    {
        a++;
        b++;
    }
    return *a - *b;
}

#define kmalloc my_kmalloc

static uint64_t mem_blocks[8];
enum { KMALLOC_CHUNK_SIZE = 1 << 22 };

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static void kmalloc_add_block(size_t min_size)
{
    size_t block_size = align_up(min_size, 4096);
    if(block_size < KMALLOC_CHUNK_SIZE)
        block_size = KMALLOC_CHUNK_SIZE;
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] || mem_blocks[i+1])
            continue;
        while(!mem_blocks[i])
            mem_blocks[i] = r0gdb_kmalloc(block_size);
        mem_blocks[i+1] = mem_blocks[i] + block_size;
        return;
    }
    die();
}

static void* kmalloc(size_t sz)
{
    sz = align_up(sz, 16);
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] + sz <= mem_blocks[i+1])
        {
            uint64_t ans = mem_blocks[i];
            mem_blocks[i] += sz;
            return (void*)ans;
        }
    }
    kmalloc_add_block(sz);
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] + sz <= mem_blocks[i+1])
        {
            uint64_t ans = mem_blocks[i];
            mem_blocks[i] += sz;
            return (void*)ans;
        }
    }
    die();
    return 0;
}

#define NCPUS 16
#define IDT (offsets.idt)
/*
 * TODO(FW_PORT): verify GDT/TSS array stride, CPU count, PCPU stride, and the
 * IST slot offsets on the new firmware.  Derive them from the per-CPU setup
 * code and confirm all populated entries, rather than extending the >= 7.00
 * assumption from one sample.
 */
#define GDT(i) (offsets.gdt_array+0x68*(i))
#define TSS(i) (offsets.tss_array+0x68*(i))
#define PCPU(i, fwver) ((fwver >= 0x700) ? (offsets.pcpu_array+0x980*(i)) : (offsets.pcpu_array+0x900*(i)))

size_t virt2file(uint64_t* phdr, uint16_t phnum, uintptr_t addr)
{
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        if(h[2] <= addr && h[2] + h[4] > addr)
            return addr + h[1] - h[2];
    }
    return -1;
}

void* load_kelf(void* ehdr, const char** symbols, uint64_t* values, void** base, void** entry, uint64_t mapped_kptr)
{
    uint64_t* phdr = (void*)((char*)ehdr + *(uint64_t*)((char*)ehdr + 32));
    uint16_t phnum = *(uint16_t*)((char*)ehdr + 56);
    uint64_t* dynamic = 0;
    size_t sz_dynamic = 0;
    uint64_t kernel_size = 0;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] == 2)
        {
            dynamic = (void*)((char*)ehdr + h[1]);
            sz_dynamic = h[4];
        }
        else if((uint32_t)h[0] == 1)
        {
            uint64_t limit = h[2] + h[5];
            if(limit > kernel_size)
                kernel_size = limit;
        }
    }
    kernel_size = ((kernel_size + 4095) | 4095) - 4095;
    char* kptr = kmalloc(kernel_size+4096);
    kptr = (char*)((((uint64_t)kptr - 1) | 4095) + 1);
    if(!mapped_kptr)
        mapped_kptr = (uint64_t)kptr;
    base[0] = kptr;
    base[1] = kptr + kernel_size;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        kmemcpy(kptr+h[2], (char*)ehdr + h[1], h[4]);
        kmemzero(kptr+h[2]+h[4], h[5]-h[4]);
    }
    char* strtab = 0;
    uint64_t* symtab = 0;
    uint64_t* rela = 0;
    size_t relasz = 0;
    for(size_t i = 0; i < sz_dynamic / 16; i++)
    {
        uint64_t* kv = dynamic + 2*i;
        if(kv[0] == 5)
            strtab = (char*)ehdr + virt2file(phdr, phnum, kv[1]);
        else if(kv[0] == 6)
            symtab = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 7)
            rela = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 8)
            relasz = kv[1];
    }
    for(size_t i = 0; i < relasz / 24; i++)
    {
        uint64_t* oia = rela + 3*i;
        if((uint32_t)oia[1] == 1 || (uint32_t)oia[1] == 6)
        {
            uint64_t* sym = symtab + 3 * (oia[1] >> 32);
            const char* name = strtab + (uint32_t)sym[0];
            uint64_t value = sym[1];
            if(!value)
            {
                for(size_t i = 0; symbols[i]; i++)
                    if(!strcmp(symbols[i], name))
                        sym[1] = value = values[i];
                    else if(symbols[i][0] == '.' && !strcmp(symbols[i]+1, name))
                        value = values[i];
#ifndef FIRMWARE_PORTING
                if(!value)
                    die();
#endif
            }
            if((uint32_t)oia[1] == 6 && oia[2])
                die();
            if(oia[0] + 8 > kernel_size)
                die();
            kpoke64(kptr+oia[0], oia[2]+value);
        }
        else if((uint32_t)oia[1] == 8)
        {
            if(oia[0] + 8 > kernel_size)
                die();
            kpoke64(kptr+oia[0], (uint64_t)(mapped_kptr+oia[2]));
        }
        else
            die();
    }
    *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

asm(".section .data\nkek:\n.incbin \"kelf\"\nkek_end:");
extern char kek[];
extern char kek_end[];

asm(".section .data\nuek:\n.incbin \"uelf/uelf.bin\"\nuek_end:");
extern char uek[];
extern char uek_end[];

asm(".section .text\nkekcall:\nmov 8(%rsp), %rax\njmp *p_kekcall(%rip)");

uint64_t kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

#define KEKCALL_GETPPID        0x000000027
#define KEKCALL_READ_DR        0x100000027
#define KEKCALL_WRITE_DR       0x200000027
#define KEKCALL_RDMSR          0x300000027
#define KEKCALL_REMOTE_SYSCALL 0x500000027
#define KEKCALL_CHECK          0xffffffff00000027

void* p_kekcall;

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t get_dmap_base(void)
{
    uint64_t ptrs[2];
    copyout(ptrs, offsets.kernel_pmap_store+32, sizeof(ptrs));
    return ptrs[0] - ptrs[1];
}

uint64_t virt2phys(uintptr_t addr, uint64_t* phys_limit, uint64_t dmap, uint64_t pml)
{
    if (!dmap) dmap = get_dmap_base();
    if (!pml) pml = r0gdb_read_cr3();
    for(int i = 39; i >= 12; i -= 9)
    {
        uint64_t inner_pml;
        copyout(&inner_pml, dmap+pml+((addr & (0x1ffull << i)) >> (i - 3)), 8);
        if(!(inner_pml & 1)) //not present
            return -1;
        if((inner_pml & 128) || i == 12) //hugepage
        {
            inner_pml &= (1ull << 52) - (1ull << i);
            inner_pml |= addr & ((1ull << i) - 1);
            if (phys_limit) *phys_limit = (inner_pml | ((1ull << i) - 1)) + 1;
            return inner_pml;
        }
        inner_pml &= (1ull << 52) - (1ull << 12);
        pml = inner_pml;
    }
    //unreachable
}

static uint64_t virt2phys_or_die(uintptr_t addr, uint64_t* phys_limit, uint64_t dmap, uint64_t pml)
{
    uint64_t phys = virt2phys(addr, phys_limit, dmap, pml);
    if(phys == (uint64_t)-1)
        die();
    return phys;
}

static void build_uelf_pml1(uint64_t pml1_virt, uint64_t user_start, uint64_t user_end, uint64_t dmap, uint64_t cr3)
{
    uint64_t phys = 0;
    uint64_t phys_end = 0;
    uint64_t vaddr = user_start;
    for(uint64_t i = 0; vaddr < user_end; i++, vaddr += 4096)
    {
        if(vaddr >= phys_end)
            phys = virt2phys_or_die(vaddr, &phys_end, dmap, cr3);
        copyin(pml1_virt+8*i, &(uint64_t[1]){phys | 7}, 8);
        phys += 4096;
    }
}

uint64_t kernel_get_proc(uint64_t pid)
{
    uint64_t proc = kread8(offsets.allproc);
    while(proc && (int)kread8(proc+0xbc) != pid)
        proc = kread8(proc);
    return proc;
}

int get_proc_cr3(uint64_t pid, uint64_t* cr3, uint64_t* dmap_base)
{
    uint64_t proc = kernel_get_proc(pid);
    if(proc == 0)
        return -1;
    uint64_t vmspace = kread8(proc + 0x200);
    /*
     * TODO(FW_PORT): verify vmspace->vm_pmap for the new firmware from the
     * kernel's vmspace/pmap accessors.  Add a new explicit range (or move this
     * into the offset table) if it is neither 0x2e0 nor 0x2e8.
     */
    uint32_t fwver = r0gdb_get_fw_version() >> 16;
    uint32_t vmspace_pmap_offset = (fwver >= 0x600) ? 0x2E8 : 0x2E0;
    uint64_t ptrs[2] = {0};
    copyout(ptrs, vmspace + vmspace_pmap_offset + 32, sizeof(ptrs));
    if (cr3) *cr3 = ptrs[1];
    if (dmap_base) *dmap_base = ptrs[0] - ptrs[1];
    return 0;
}

int phys_copyin(uint64_t vaddr, const void* src, uint64_t sz, uint64_t dmap, uint64_t pml)
{
    const char* p_src = src;
    uint64_t phys, phys_end;
    while(sz)
    {
        phys = virt2phys(vaddr, &phys_end, dmap, pml);
        if(phys == -1)
            return -1;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        copyin(dmap+phys, p_src, chk);
        vaddr += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

static int phys_copyout(void* dst, uint64_t vaddr, uint64_t sz,
                        uint64_t dmap, uint64_t pml)
{
    char* p_dst = dst;
    uint64_t phys, phys_end;
    while(sz)
    {
        phys = virt2phys(vaddr, &phys_end, dmap, pml);
        if(phys == -1)
            return -1;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        copyout(p_dst, dmap + phys, chk);
        vaddr += chk;
        p_dst += chk;
        sz -= chk;
    }
    return 0;
}

uint64_t find_empty_pml4_index(int idx)
{
    uint64_t dmap = get_dmap_base();
    uint64_t cr3 = r0gdb_read_cr3();
    uint64_t pml4[512];
    copyout(pml4, dmap+cr3, 4096);
    for(int i = 256; i < 512; i++)
        if(!pml4[i] && !idx--)
            return i;
}

enum { UELF_SHARED_AREA_OFFSET = 0x1f0000 };

/*
 * shared_area grew beyond one page when PPR staging was added. Kernel malloc
 * provides contiguous virtual space, not necessarily contiguous physical
 * pages, so translating only its first byte and adding offsets can corrupt an
 * unrelated page. Map every backing page explicitly into each uelf CR3.
 */
static void build_uelf_shared_area_mapping(uint64_t pml1_virt,
                                           uint64_t kernel_address,
                                           uint64_t user_address,
                                           uint64_t uelf_virt_base,
                                           uint64_t dmap,
                                           uint64_t cr3)
{
    if((kernel_address & 4095) || (user_address & 4095)
    || (SHARED_AREA_SIZE & 4095)
    || user_address < uelf_virt_base
    || user_address + SHARED_AREA_SIZE < user_address
    || user_address + SHARED_AREA_SIZE > uelf_virt_base + 0x200000)
        die();

    uint64_t pte = (user_address - uelf_virt_base) >> 12;
    for(uint64_t offset = 0; offset < SHARED_AREA_SIZE; offset += 4096)
    {
        uint64_t phys = virt2phys_or_die(kernel_address + offset, 0,
                                        dmap, cr3);
        copyin(pml1_virt + 8 * (pte + offset / 4096),
               &(uint64_t[1]){phys | 7}, 8);
    }
}

void build_uelf_cr3(uint64_t uelf_cr3, void* uelf_base[2],
                    uint64_t uelf_virt_base, uint64_t dmap_virt_base,
                    uint64_t shared_area_kernel,
                    uint64_t shared_area_user,
                    uint64_t dmap, uint64_t cr3)
{
    enum
    {
        X86_PG_V = 1,
        X86_PG_RW = 2,
        X86_PG_U = 4,
        X86_PG_PS = 1 << 7,
    };
    const uint64_t user_page = X86_PG_V | X86_PG_RW | X86_PG_U;
    const uint64_t user_large_page = user_page | X86_PG_PS;
    static char zeros[4096];
    uint64_t user_start = (uint64_t)uelf_base[0];
    uint64_t user_end = (uint64_t)uelf_base[1];
    if((uelf_virt_base & 0x1fffff)
    || (dmap_virt_base & ((1ull << 39) - 1))
    || user_end - user_start > UELF_SHARED_AREA_OFFSET)
        die();
    uint64_t pml4_virt = uelf_cr3;
    copyin(pml4_virt, zeros, 4096);
    kmemcpy((void*)(pml4_virt+2048), (void*)(dmap+cr3+2048), 2048);
    uint64_t pml3_virt = uelf_cr3 + 4096;
    uint64_t pml3_dmap = uelf_cr3 + 16384; //user-accessible direct mapping of physical memory
    copyin(pml4_virt + 8 * ((uelf_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys_or_die(pml3_virt, 0, dmap, cr3) | user_page}, 8);
    copyin(pml4_virt + 8 * ((dmap_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys_or_die(pml3_dmap, 0, dmap, cr3) | user_page}, 8);
    copyin(pml3_virt, zeros, 4096);
    uint64_t pml2_virt = uelf_cr3 + 8192;
    copyin(pml3_virt + 8 * ((uelf_virt_base >> 30) & 511), &(uint64_t[1]){virt2phys_or_die(pml2_virt, 0, dmap, cr3) | user_page}, 8);
    copyin(pml2_virt, zeros, 4096);
    uint64_t pml1_virt = uelf_cr3 + 12288;
    copyin(pml2_virt + 8 * ((uelf_virt_base >> 21) & 511), &(uint64_t[1]){virt2phys_or_die(pml1_virt, 0, dmap, cr3) | user_page}, 8);
    copyin(pml1_virt, zeros, 4096);
    build_uelf_pml1(pml1_virt, user_start, user_end, dmap, cr3);
    build_uelf_shared_area_mapping(pml1_virt, shared_area_kernel,
                                   shared_area_user, uelf_virt_base,
                                   dmap, cr3);
    for(uint64_t i = 0; i < 512; i++)
        copyin(pml3_dmap+8*i, &(uint64_t[1]){(i<<30) | user_large_page}, 8);
}

int find_proc(const char* name)
{
    for(int pid = 1; pid < 1024; pid++)
    {
        size_t sz = 1096;
        int key[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        char buf[1097] = {0};
        sysctl(key, 4, buf, &sz, 0, 0);
        const char* a = buf + 447;
        const char* b = name;
        while(*a && *a++ == *b++);
        if(!*a && !*b)
            return pid;
    }
    return -1;
}

static uint64_t remote_syscall(int pid, int nr, ...)
{
    va_list va;
    va_start(va, nr);
    uint64_t args[6];
    for(int i = 0; i < 6; i++)
        args[i] = va_arg(va, uint64_t);
    va_end(va);
    return kekcall(pid, nr, (uint64_t)args, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
}

#define SYS_mlock 203
#define SYS_mdbg_call 573
#define SYS_dynlib_get_info_ex 608
#define SYS_dynlib_load_prx 594
#define SYS_get_self_auth_info 607
#define SYS_get_sdk_compiled_version 647
#define SYS_get_ppr_sdk_compiled_version 713

struct module_segment
{
    uint64_t addr;
    uint32_t size;
    uint32_t flags;
};

struct module_info_ex
{
    size_t st_size;
    char name[256];
    int id;
    uint32_t tls_index;
    uint64_t tls_init_addr;
    uint32_t tls_init_size;
    uint32_t tls_size;
    uint32_t tls_offset;
    uint32_t tls_align;
    uint64_t init_proc_addr;
    uint64_t fini_proc_addr;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t eh_frame_hdr_addr;
    uint64_t eh_frame_addr;
    uint32_t eh_frame_hdr_size;
    uint32_t eh_frame_size;
    struct module_segment segments[4];
    uint32_t segment_count;
    uint32_t ref_count;
};

struct shellcore_patch
{
    uint64_t offset;
    char* data;
    size_t sz;
};

/*
 * TODO(FW_PORT): add shellcore_patches/<major>_<minor>.h here after deriving
 * every patch from that exact SceShellCore build.  Patch offsets are relative
 * to the module image; verify original bytes and the retail/testkit/devkit
 * variants before enabling the firmware.
 */
#include "shellcore_patches/2_50.h"
#include "shellcore_patches/3_00.h"
#include "shellcore_patches/3_10.h"
#include "shellcore_patches/3_20.h"
#include "shellcore_patches/3_21.h"
#include "shellcore_patches/4_00.h"
#include "shellcore_patches/4_02.h"
#include "shellcore_patches/4_03.h"
#include "shellcore_patches/4_50.h"
#include "shellcore_patches/4_51.h"
#include "shellcore_patches/5_00.h"
#include "shellcore_patches/5_02.h"
#include "shellcore_patches/5_10.h"
#include "shellcore_patches/5_50.h"
#include "shellcore_patches/6_00.h"
#include "shellcore_patches/6_02.h"
#include "shellcore_patches/6_50.h"
#include "shellcore_patches/7_00.h"
#include "shellcore_patches/7_01.h"
#include "shellcore_patches/7_20.h"
#include "shellcore_patches/7_40.h"
#include "shellcore_patches/7_60.h"
#include "shellcore_patches/7_61.h"
#include "shellcore_patches/8_00.h"
#include "shellcore_patches/8_20.h"
#include "shellcore_patches/8_40.h"
#include "shellcore_patches/8_60.h"
#include "shellcore_patches/9_05.h"
#include "shellcore_patches/9_00.h"
#include "shellcore_patches/9_20.h"
#include "shellcore_patches/9_40.h"
#include "shellcore_patches/9_60.h"
#include "shellcore_patches/10_00.h"
#include "shellcore_patches/10_01.h"
#include "shellcore_patches/10_20.h"
#include "shellcore_patches/10_40.h"
#include "shellcore_patches/10_60.h"
#include "shellcore_patches/11_00.h"
#include "shellcore_patches/11_20.h"
#include "shellcore_patches/11_40.h"
#include "shellcore_patches/11_60.h"
#include "shellcore_patches/12_00.h"
#include "shellcore_patches/12_02.h"
#include "shellcore_patches/12_20.h"
#include "shellcore_patches/12_40.h"
#include "shellcore_patches/12_60.h"
#include "shellcore_patches/12_70.h"

extern char _start[];

static void relocate_shellcore_patches(struct shellcore_patch* patches, size_t n_patches)
{
    static uint64_t start_nonreloc = (uint64_t)_start;
    uint64_t start = (uint64_t)_start;
    for(size_t i = 0; i < n_patches; i++)
        patches[i].data += start - start_nonreloc;
}

uint64_t get_eh_frame_offset(const char* path)
{
    int fd = open(path, O_RDONLY);
    if(!fd)
        return 0;
    unsigned long long shit[4];
    if(read(fd, shit, sizeof(shit)) != sizeof(shit))
    {
        close(fd);
        return 0;
    }
    off_t o2 = 0x20*((shit[3]&0xffff)+1);
    lseek(fd, o2, SEEK_SET);
    unsigned long long ehdr[8];
    if(read(fd, ehdr, sizeof(ehdr)) != sizeof(ehdr))
    {
        close(fd);
        return 0;
    }
    off_t phdr_offset = o2 + ehdr[4];
    int nphdr = ehdr[7] & 0xffff;
    unsigned long long eh_frame = 0;
    lseek(fd, phdr_offset, SEEK_SET);
    for(int i = 0; i < nphdr; i++)
    {
        unsigned long long phdr[7];
        if(read(fd, phdr, sizeof(phdr)) != sizeof(phdr))
        {
            close(fd);
            return 0;
        }
        unsigned long long addr = phdr[2];
        int ptype = phdr[0] & 0xffffffff;
        if(ptype == 0x6474e550)
            eh_frame = addr;
    }
    close(fd);
    return eh_frame;
}

bool if_exists(const char *path) {
    struct stat buffer;
    return stat(path, &buffer) == 0;
}

bool sceKernelIsTestKit(void) {
    return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}

bool sceKernelIsDevKit(void) {
    return if_exists("/system/priv/lib/libSceDeci5Dtracep.sprx");
}

enum kit_type {
    KIT_RETAIL,
    KIT_TESTKIT,
    KIT_DEVKIT
};

static enum kit_type get_kit_type(void) {
    if (sceKernelIsDevKit())   return KIT_DEVKIT;
    if (sceKernelIsTestKit())  return KIT_TESTKIT;
    return KIT_RETAIL;
}

extern const unsigned char ppr_mount_940_blob_start[];
extern const unsigned char ppr_mount_940_blob_end[];

enum {
    SHELLCORE_940_PPR_CALL_OFFSET = 0x748D0D,
    SHELLCORE_940_PPR_CAVE_OFFSET = 0x17DEB50,
    SHELLCORE_940_PPR_CAVE_SIZE = 0x4B0,
    SHELLCORE_940_OPEN_PLT_OFFSET = 0x17D6F00,
    LIBKERNEL_SYS_940_OPEN_OFFSET = 0xF290,
    LIBKERNEL_SYS_940_GETPID_OFFSET = 0x5B0,
};

#define SHELLCORE_PPR_SYSCALL_PLACEHOLDER 0x4C43535953525050ull

static const char* shellcore_patch_failure;

static int shellcore_ppr_fail(const char* reason)
{
    shellcore_patch_failure = reason;
    return -1;
}

static int bytes_equal(const unsigned char* a, const unsigned char* b,
                       size_t size)
{
    for(size_t i = 0; i < size; i++)
        if(a[i] != b[i])
            return 0;
    return 1;
}

static int install_shellcore_ppr_hook_940(int pid, uint64_t shellcore_base,
                                           uint64_t dmap, uint64_t cr3)
{
    static const unsigned char expected_call[5] = {
        0xE8, 0xCE, 0x05, 0x09, 0x01
    };
    const size_t blob_size = (size_t)(ppr_mount_940_blob_end
                                    - ppr_mount_940_blob_start);
    unsigned char prepared_blob[SHELLCORE_940_PPR_CAVE_SIZE];
    unsigned char current_call[sizeof(expected_call)];
    unsigned char call_patch[sizeof(expected_call)] = {0xE8};
    unsigned char chunk[64];
    int cave_is_zero = 1;
    int cave_is_blob = 1;

    if(!blob_size || blob_size > SHELLCORE_940_PPR_CAVE_SIZE)
        return shellcore_ppr_fail("PPR hook: invalid blob size");

    static const unsigned char expected_open_plt[] = {
        0xFF, 0x25, 0x1A, 0x04, 0x6A, 0x00
    };
    if(phys_copyout(chunk,
                    shellcore_base + SHELLCORE_940_OPEN_PLT_OFFSET,
                    sizeof(expected_open_plt), dmap, cr3)
    || !bytes_equal(chunk, expected_open_plt, sizeof(expected_open_plt)))
        return shellcore_ppr_fail("PPR hook: open PLT mismatch");

    int32_t open_got_displacement;
    memcpy(&open_got_displacement, expected_open_plt + 2,
           sizeof(open_got_displacement));
    uint64_t open_got = shellcore_base + SHELLCORE_940_OPEN_PLT_OFFSET
                      + sizeof(expected_open_plt) + open_got_displacement;
    uint64_t open_address;
    if(phys_copyout(&open_address, open_got, sizeof(open_address), dmap, cr3)
    || open_address < LIBKERNEL_SYS_940_OPEN_OFFSET)
        return shellcore_ppr_fail("PPR hook: open GOT read failed");
    uint64_t libkernel_sys_base = open_address
                                - LIBKERNEL_SYS_940_OPEN_OFFSET;
    if(libkernel_sys_base + LIBKERNEL_SYS_940_GETPID_OFFSET
       < libkernel_sys_base)
        return shellcore_ppr_fail("PPR hook: libkernel address overflow");
    uint64_t getpid_address = libkernel_sys_base
                            + LIBKERNEL_SYS_940_GETPID_OFFSET;
    uint64_t syscall_target = getpid_address + 7;
    if(syscall_target < getpid_address)
        return shellcore_ppr_fail("PPR hook: syscall address overflow");

    static const unsigned char expected_syscall_target[] = {
        0x49, 0x89, 0xCA, 0x0F, 0x05, 0x72, 0x01, 0xC3
    };
    if(remote_syscall(pid, SYS_mlock, syscall_target,
                      (uint64_t)sizeof(expected_syscall_target), 0, 0, 0, 0)
    || phys_copyout(chunk, syscall_target, sizeof(expected_syscall_target),
                    dmap, cr3)
    || !bytes_equal(chunk, expected_syscall_target,
                    sizeof(expected_syscall_target)))
        return shellcore_ppr_fail("PPR hook: syscall trampoline mismatch");

    memcpy(prepared_blob, ppr_mount_940_blob_start, blob_size);
    size_t syscall_placeholder_count = 0;
    for(size_t offset = 0; offset + sizeof(uint64_t) <= blob_size; offset++)
    {
        uint64_t value;
        memcpy(&value, prepared_blob + offset, sizeof(value));
        if(value != SHELLCORE_PPR_SYSCALL_PLACEHOLDER)
            continue;
        memcpy(prepared_blob + offset, &syscall_target,
               sizeof(syscall_target));
        syscall_placeholder_count++;
    }
    if(syscall_placeholder_count != 1)
        return shellcore_ppr_fail("PPR hook: syscall placeholder mismatch");

    int32_t displacement = SHELLCORE_940_PPR_CAVE_OFFSET
                         - (SHELLCORE_940_PPR_CALL_OFFSET + 5);
    memcpy(call_patch + 1, &displacement, sizeof(displacement));

    /* This also proves that the page-rounded tail beyond p_memsz is present
     * in the live ShellCore vm_map before any bytes are changed. */
    if(remote_syscall(pid, SYS_mlock,
                      shellcore_base + SHELLCORE_940_PPR_CAVE_OFFSET,
                      SHELLCORE_940_PPR_CAVE_SIZE, 0, 0, 0, 0))
        return shellcore_ppr_fail("PPR hook: cave mlock failed");

    if(phys_copyout(current_call,
                    shellcore_base + SHELLCORE_940_PPR_CALL_OFFSET,
                    sizeof(current_call), dmap, cr3))
        return shellcore_ppr_fail("PPR hook: call-site read failed");
    int call_is_original = bytes_equal(current_call, expected_call,
                                       sizeof(expected_call));
    int call_is_hook = bytes_equal(current_call, call_patch,
                                   sizeof(call_patch));
    if(!call_is_original && !call_is_hook)
        return shellcore_ppr_fail("PPR hook: call-site mismatch");

    /* Accept either an untouched cave or this exact blob followed by zeros.
     * The latter makes reloads and recovery after an interrupted install
     * idempotent without accepting another resident patch. */
    for(size_t offset = 0; offset < SHELLCORE_940_PPR_CAVE_SIZE;
        offset += sizeof(chunk))
    {
        size_t size = SHELLCORE_940_PPR_CAVE_SIZE - offset;
        if(size > sizeof(chunk))
            size = sizeof(chunk);
        if(phys_copyout(chunk,
                        shellcore_base + SHELLCORE_940_PPR_CAVE_OFFSET + offset,
                        size, dmap, cr3))
            return shellcore_ppr_fail("PPR hook: cave read failed");
        for(size_t i = 0; i < size; i++)
        {
            if(chunk[i])
                cave_is_zero = 0;
            unsigned char expected = offset + i < blob_size
                                   ? prepared_blob[offset + i]
                                   : 0;
            if(chunk[i] != expected)
                cave_is_blob = 0;
        }
    }

    if(call_is_hook)
        return cave_is_blob ? 0
             : shellcore_ppr_fail("PPR hook: resident blob mismatch");
    if(!cave_is_zero && !cave_is_blob)
        return shellcore_ppr_fail("PPR hook: cave is occupied");

    if(cave_is_zero)
    {
        if(phys_copyin(shellcore_base + SHELLCORE_940_PPR_CAVE_OFFSET,
                       prepared_blob, blob_size, dmap, cr3))
            return shellcore_ppr_fail("PPR hook: cave write failed");

        /* Verify the resident blob before making it reachable. */
        for(size_t offset = 0; offset < blob_size; offset += sizeof(chunk))
        {
            size_t size = blob_size - offset;
            if(size > sizeof(chunk))
                size = sizeof(chunk);
            if(phys_copyout(
                    chunk,
                    shellcore_base + SHELLCORE_940_PPR_CAVE_OFFSET + offset,
                    size, dmap, cr3)
            || !bytes_equal(chunk, prepared_blob + offset, size))
                return shellcore_ppr_fail("PPR hook: cave verify failed");
        }
    }

    /* call 0x17DEB50 from 0x748D0D; install this redirection last. */
    if(phys_copyin(shellcore_base + SHELLCORE_940_PPR_CALL_OFFSET,
                   call_patch, sizeof(call_patch), dmap, cr3))
        return shellcore_ppr_fail("PPR hook: call-site write failed");

    if(phys_copyout(current_call,
                    shellcore_base + SHELLCORE_940_PPR_CALL_OFFSET,
                    sizeof(current_call), dmap, cr3)
    || !bytes_equal(current_call, call_patch, sizeof(call_patch)))
        return shellcore_ppr_fail("PPR hook: call-site verify failed");
    return 0;
}

static const struct shellcore_patch* get_shellcore_patches(size_t* n_patches)
{
enum kit_type kit = get_kit_type();
	
#define FW(x) \
    case 0x ## x:\
        switch (kit) { \
            case KIT_DEVKIT: \
                *n_patches = sizeof(shellcore_patches_##x##_devkit) / sizeof(*shellcore_patches_##x##_devkit);\
                patches = shellcore_patches_##x##_devkit;\
                break; \
            case KIT_TESTKIT: \
                *n_patches = sizeof(shellcore_patches_##x##_testkit) / sizeof(*shellcore_patches_##x##_testkit);\
                patches = shellcore_patches_##x##_testkit;\
                break; \
            case KIT_RETAIL: \
                *n_patches = sizeof(shellcore_patches_##x##_retail) / sizeof(*shellcore_patches_##x##_retail);\
                patches = shellcore_patches_##x##_retail;\
                break; \
        } \
        break
	
    uint32_t ver = r0gdb_get_fw_version() >> 16;
    struct shellcore_patch* patches;
    switch(ver)
    {
    /* TODO(FW_PORT): add FW(<version>) after including its verified table. */
    FW(250);
    FW(300);
    FW(310);
    FW(320);
    FW(321);
    FW(400);
    FW(402);
    FW(403);
    FW(450);
    FW(451);
    FW(500);
    FW(502);
    FW(510);
    FW(550);
    FW(600);
    FW(602);
    FW(650);
    FW(700);
    FW(701);
    FW(720);
    FW(740);
    FW(760);
    FW(761);
    FW(800);
    FW(820);
    FW(840);
    FW(860);
    FW(900);
    FW(905);
    FW(920);
    FW(940);
    FW(960);
    FW(1000);
    FW(1001);
    FW(1020);
    FW(1040);
    FW(1060);
    FW(1100);
    FW(1120);
    FW(1140);
    FW(1160);
    FW(1200);
    FW(1202);
    FW(1220);
    FW(1240);
    FW(1260);
    FW(1270);

    default:
        *n_patches = 1;
        return 0;
    }
#undef FW
    relocate_shellcore_patches(patches, *n_patches);
    return patches;
}

static int patch_shellcore(const struct shellcore_patch* patches, size_t n_patches, uint64_t eh_frame_offset)
{
    shellcore_patch_failure = 0;
    int pid = find_proc("SceShellCore");
    struct module_info_ex mod_info;
    mod_info.st_size = sizeof(mod_info);
    if (remote_syscall(pid, SYS_dynlib_get_info_ex, 0, 0, &mod_info))
        return -1;
    uint64_t shellcore_base = mod_info.eh_frame_hdr_addr - eh_frame_offset;
    uint64_t textsize = mod_info.segments[0].size;
    if (remote_syscall(pid, SYS_mlock, shellcore_base, textsize))
        return -1;
    uint64_t cr3, dmap;
    if(get_proc_cr3(pid, &cr3, &dmap))
        return -1;

    for(int i = 0; i < n_patches; i++)
    {
        if(phys_copyin(shellcore_base + patches[i].offset, patches[i].data, patches[i].sz, dmap, cr3))
            return -1;
    }
    if((r0gdb_get_fw_version() >> 16) == 0x940
    && get_kit_type() == KIT_RETAIL
    && install_shellcore_ppr_hook_940(pid, shellcore_base, dmap, cr3))
        return -1;
    return 0;
}

#ifndef DEBUG
#define dbg_enter()
#define gdb_remote_syscall(...)
#endif

static inline uint64_t rdtsc(void)
{
    uint32_t eax, edx;
    asm volatile("rdtsc":"=a"(eax),"=d"(edx)::"memory");
    return (uint64_t)edx << 32 | eax;
}

//without kstuff = 2308259098
//with kstuff and in-kelf checks = 86633419408 (37.5 times slower)
//with kstuff and no in-kelf checks = 68129284331 (39.5 times slower)
uint64_t bench(void)
{
    uint64_t start = rdtsc();
    for(int i = 0; i < 1000000; i++)
        getpid();
    return rdtsc() - start;
}

#define USE_INT3_SYSCALL_HOOK 1
#define INT13_IST_INDEX 3
#define INT1_IST_INDEX 4
#define INT3_IST_INDEX 7

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    snprintf = dlsym((void*)0x2, "snprintf");

    if(r0gdb_init(ds, a, b, c, d))
    {
#ifndef FIRMWARE_PORTING
        notify("your firmware is not supported (prosper0gdb)");
        return 1;
#endif
    }
#ifdef PS5KEK
    extern uint64_t p_syscall;
    getpid();
    p_kekcall = (void*)p_syscall;
#else
    p_kekcall = (char*)dlsym((void*)0x1, "getpid") + 7;
#endif
    if(!kekcall(0, 0, 0, 0, 0, 0, 0xffffffff00000027))
    {
        notify("ps5-kstuff is already loaded");
        return 1;
    }

    size_t n_shellcore_patches;
    uint64_t shellcore_eh_frame_offset = get_eh_frame_offset("/system/vsh/SceShellCore.elf");
    const struct shellcore_patch* shellcore_patches = get_shellcore_patches(&n_shellcore_patches);
    if(n_shellcore_patches && !shellcore_patches)
    {
#ifdef FIRMWARE_PORTING
        n_shellcore_patches = 0;
#else
        notify("your firmware is not supported (shellcore)");
        return 1;
#endif
    }
#ifdef FIRMWARE_PORTING
    dbg_enter();
#endif

    uint64_t percpu_ist4[NCPUS];
    for(int cpu = 0; cpu < NCPUS; cpu++)
        copyout(&percpu_ist4[cpu], TSS(cpu)+28+4*8, 8);
    uint64_t int1_handler;
    copyout(&int1_handler, IDT+16*1, 2);
    copyout((char*)&int1_handler + 2, IDT+16*1+6, 6);
    uint64_t int3_handler;
    copyout(&int3_handler, IDT+16*3, 2);
    copyout((char*)&int3_handler + 2, IDT+16*3+6, 6);
    uint64_t int13_handler;
    copyout(&int13_handler, IDT+16*13, 2);
    copyout((char*)&int13_handler + 2, IDT+16*13+6, 6);
#ifndef FIRMWARE_PORTING
    dbg_enter();
#endif
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"allocating kernel memory... ", (uintptr_t)28);

#ifdef USE_INT3_SYSCALL_HOOK
    // this jmp to int3 exists because sony fills certain functions with int3 depending on the console type
    // retails have the most of these redacted functions, testkits less, devkits even less, presumably "DevKit Intdev" has none
    // the built in offsets are mostly from retail firmwares so for kits we need to find them again
    int is_kit = sceKernelIsTestKit() || sceKernelIsDevKit();
    if (offsets.syscall_cfi_table_jmp_int3 == kdata_base || is_kit) {
        offsets.syscall_cfi_table_jmp_int3 = r0gdb_find_syscall_cfi_table_jmp_int3_addr();
        if (offsets.syscall_cfi_table_jmp_int3 == 0 || offsets.syscall_cfi_table_jmp_int3 == kdata_base)
            die();

        // from the 1 fw i checked, everything redacted on kits is also redacted on retails
        // so kit offsets should work on retails, but to be safe, in case this changes in the future
        // only report the offset if from a retail console
        if (!is_kit) {
            int64_t syscall_cfi_table_jmp_int3_offset = offsets.syscall_cfi_table_jmp_int3 - kdata_base;
            char log[128];
            snprintf(log, sizeof(log), "syscall_cfi_table_jmp_int3 offset missing.\nPlease contribute this offset: %s0x%llx", (offsets.syscall_cfi_table_jmp_int3 > kdata_base) ? "+" : "-", (syscall_cfi_table_jmp_int3_offset > 0) ? syscall_cfi_table_jmp_int3_offset : -syscall_cfi_table_jmp_int3_offset);
            notify(log);
        }
    }
#endif

    for(int i = 0; i < 0x300; i += 2)
        r0gdb_kmalloc(0x100);
    kmalloc_add_block(KMALLOC_CHUNK_SIZE);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    uint64_t comparison_table_base = (uint64_t)kmalloc(131072);
    uint64_t comparison_table = ((comparison_table_base - 1) | 65535) + 1;
    uint8_t* comparison_table_data = mmap(0, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    for(size_t i = 0; i < 256; i++)
        for(size_t j = 0; j < 256; j++)
            comparison_table_data[256*i+j] = 8*(1+(i>j)-(i<j));
    //trying to copyin the whole 64k at once hangs here for some reason
    for(size_t i = 0; i < 256; i++)
        copyin(comparison_table+256*i, comparison_table_data+256*i, 256);
    uint64_t shared_area_kernel;
    if(comparison_table - comparison_table_base > SHARED_AREA_SIZE)
        shared_area_kernel = comparison_table - SHARED_AREA_SIZE;
    else
        shared_area_kernel = comparison_table + 65536;
    kmemzero((void*)shared_area_kernel, SHARED_AREA_SIZE);
    uint64_t kernel_dmap = get_dmap_base();
    uint64_t kernel_cr3 = r0gdb_read_cr3();
    uint64_t uelf_virt_base = (find_empty_pml4_index(0) << 39) | (-1ull << 48);
    uint64_t dmem_virt_base = (find_empty_pml4_index(1) << 39) | (-1ull << 48);
    uint64_t shared_area_user = uelf_virt_base + UELF_SHARED_AREA_OFFSET;

    volatile int zero = 0; //hack to force runtime calculation of string pointers
    const char* symbols[] = {
        "comparison_table"+zero,
        "dmem"+zero,
        "int1_handler"+zero,
        "int3_handler"+zero,
        "int13_handler"+zero,
        ".ist_errc"+zero,
        ".ist_noerrc"+zero,
        ".ist4"+zero,
        ".pcpu"+zero,
        "shared_area"+zero,
        ".tss"+zero,
        ".uelf_cr3"+zero,
        ".uelf_entry"+zero,
        ".fwver"+zero,
#define KDATA_OFFSET(x) (#x)+zero,
#define ABSOLUTE_OFFSET(x) (#x)+zero,
#include "../prosper0gdb/offsets/offset_list.txt"
#undef KDATA_OFFSET
#undef ABSOLUTE_OFFSET
        0,
    };
	
    uint64_t fwver = r0gdb_get_fw_version() >> 16;
    uint64_t values[] = {
        comparison_table,      // comparison_table
        dmem_virt_base,        // dmem
        int1_handler,          // int1_handler
        int3_handler,          // int3_handler
        int13_handler,         // int13_handler
        0x1237,                // .ist_errc
        0x1238,                // .ist_noerrc
        0x1239,                // .ist4
        0x1234,                // .pcpu
        shared_area_user,      // shared_area
        0x123a,                // .tss
        0x1235,                // .uelf_cr3
        0x1236,                // .uelf_entry
        fwver,                 // .fwver
#define KDATA_OFFSET(x) offsets.x,
#define ABSOLUTE_OFFSET(x) offsets.x,
#include "../prosper0gdb/offsets/offset_list.txt"
#undef KDATA_OFFSET
#undef ABSOLUTE_OFFSET
        0,
    };
    size_t pcpu_idx, uelf_cr3_idx, uelf_entry_idx, ist_errc_idx, ist_noerrc_idx, ist4_idx, tss_idx;
    for(size_t i = 0; values[i]; i++)
        switch(values[i])
        {
        case 0x1234: pcpu_idx = i; break;
        case 0x1235: uelf_cr3_idx = i; break;
        case 0x1236: uelf_entry_idx = i; break;
        case 0x1237: ist_errc_idx = i; break;
        case 0x1238: ist_noerrc_idx = i; break;
        case 0x1239: ist4_idx = i; break;
        case 0x123a: tss_idx = i; break;
        }
    uint64_t uelf_bases[NCPUS];
    uint64_t kelf_bases[NCPUS];
    uint64_t kelf_entries[NCPUS];
    uint64_t uelf_cr3s[NCPUS];
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        char buf[] = "loading on cpu ..\n";
        if(cpu >= 10)
        {
            buf[15] = '1';
            buf[16] = (cpu - 10) + '0';
            gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)buf, (uintptr_t)18);
        }
        else
        {
            buf[15] = cpu + '0';
            buf[16] = '\n';
            gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)buf, (uintptr_t)17);
        }
        values[pcpu_idx] = PCPU(cpu, fwver);
        values[uelf_cr3_idx] = 0;
        values[uelf_entry_idx] = 0;
        values[ist_errc_idx] = TSS(cpu)+28+INT13_IST_INDEX*8;
        values[ist_noerrc_idx] = TSS(cpu)+28+INT1_IST_INDEX*8;
        values[ist4_idx] = percpu_ist4[cpu];
        values[tss_idx] = TSS(cpu);
        void* uelf_entry = 0;
        void* uelf_base[2] = {0};
        char* uelf = load_kelf(uek, symbols, values, uelf_base, &uelf_entry, uelf_virt_base);
        uintptr_t uelf_cr3 = (uintptr_t)kmalloc(24576);
        uelf_cr3 = ((uelf_cr3 + 4095) | 4095) - 4095;
        uelf_cr3s[cpu] = uelf_cr3;
        values[uelf_cr3_idx] = virt2phys_or_die(uelf_cr3, 0, kernel_dmap, kernel_cr3);
        values[uelf_entry_idx] = (uintptr_t)uelf_entry - (uintptr_t)uelf_base[0] + uelf_virt_base;
        void* entry = 0;
        void* base[2] = {0};
        char* kelf = load_kelf(kek, symbols, values, base, &entry, 0);
        build_uelf_cr3(uelf_cr3, uelf_base, uelf_virt_base, dmem_virt_base,
                       shared_area_kernel, shared_area_user,
                       kernel_dmap, kernel_cr3);
        uelf_bases[cpu] = (uintptr_t)uelf;
        kelf_bases[cpu] = (uint64_t)kelf;
        kelf_entries[cpu] = (uint64_t)entry;
    }
    r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) | 0x100);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done loading\npatching idt... ", (uintptr_t)29);
    uint64_t cr3 = r0gdb_read_cr3();
    
    uint64_t iret = offsets.doreti_iret;
    kmemcpy((char*)(IDT+16*2), (char*)&iret, 2);
    kmemcpy((char*)(IDT+16*2+6), (char*)&iret+2, 6);

    uint64_t entry0 = kelf_entries[0];
    kmemcpy((char*)IDT+16*13, (char*)entry0, 2);
    kmemcpy((char*)IDT+16*13+6, (char*)entry0+2, 6);
    kmemcpy((char*)IDT+16*13+4, &(uint8_t){INT13_IST_INDEX}, 1);
    kmemcpy((char*)IDT+16*1, (char*)entry0+16, 2);
    kmemcpy((char*)IDT+16*1+6, (char*)entry0+18, 6);
    kmemcpy((char*)IDT+16*1+4, &(uint8_t){INT1_IST_INDEX}, 1);

#ifdef USE_INT3_SYSCALL_HOOK
    kmemcpy((char*)IDT+16*3, (char*)entry0+32, 2);
    kmemcpy((char*)IDT+16*3+6, (char*)entry0+34, 6);
    kmemcpy((char*)IDT+16*3+4, &(uint8_t){INT3_IST_INDEX}, 1);
#endif

    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        uint64_t entry = kelf_entries[cpu];
        kmemcpy((char*)TSS(cpu)+28+INT13_IST_INDEX*8, (char*)entry+8, 8);
        kmemcpy((char*)TSS(cpu)+28+INT1_IST_INDEX*8, (char*)entry+24, 8);
#ifdef USE_INT3_SYSCALL_HOOK
        kmemcpy((char*)TSS(cpu)+28+INT3_IST_INDEX*8, (char*)entry+40, 8);
#endif
    }

    //kmemzero((char*)(IDT+16*1), 16);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\napplying kdata patches... ", (uintptr_t)31);


#ifdef USE_INT3_SYSCALL_HOOK
    static const int syscalls_to_hook_for_ps4[] = {
        SYS_execve,
        SYS_dynlib_load_prx,
        SYS_get_self_auth_info,
        SYS_get_sdk_compiled_version,
        SYS_getppid,
        SYS_mprotect
    };
    static const int num_syscalls_to_hook_for_ps4 = sizeof(syscalls_to_hook_for_ps4) / sizeof(syscalls_to_hook_for_ps4[0]);

    static const int syscalls_to_hook_for_ps5[] = {
        SYS_execve,
        SYS_dynlib_load_prx,
        SYS_get_self_auth_info,
        SYS_get_sdk_compiled_version,
        SYS_get_ppr_sdk_compiled_version,
        SYS_getppid,
        SYS_nmount,
        SYS_unmount,
        SYS_mprotect,
        SYS_mdbg_call
    };
    static const int num_syscalls_to_hook_for_ps5 = sizeof(syscalls_to_hook_for_ps5) / sizeof(syscalls_to_hook_for_ps5[0]);

    // ioctl is only used for the npdrm hook, which is only used by shellcore, avoid the overhead of hooking every ioctl for every proc
    // TODO: handle npdrm hook in userland?
    static const int extra_syscalls_to_hook_for_shellcore[] = {
        SYS_ioctl
    };
    static const int num_extra_syscalls_to_hook_for_shellcore = sizeof(extra_syscalls_to_hook_for_shellcore) / sizeof(extra_syscalls_to_hook_for_shellcore[0]);

    int ps4_sv_table_size = ((int)kread8(offsets.sysentvec_ps4)) * sizeof(struct sysent);
    int ps5_sv_table_size = ((int)kread8(offsets.sysentvec)) * sizeof(struct sysent);
        
    // avoid writing to sysents directly, make copies and set those in the sysentvec
    // the uelf needs the og values anyway and this also saves us from needing a primitive to write to rodata
    char* ps4_sv_table = mmap(0, ps4_sv_table_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    char* ps5_sv_table = mmap(0, ps5_sv_table_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    char* shellcore_ps5_sv_table = mmap(0, ps5_sv_table_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (ps4_sv_table == MAP_FAILED || ps5_sv_table == MAP_FAILED || shellcore_ps5_sv_table == MAP_FAILED)
        die();

    copyout(ps4_sv_table, offsets.sysents_ps4, ps4_sv_table_size);
    copyout(ps5_sv_table, offsets.sysents, ps5_sv_table_size);
    
    for (int i = 0; i < num_syscalls_to_hook_for_ps4; i++)
    {
        int syscall = syscalls_to_hook_for_ps4[i];
        *((uint64_t*)(ps4_sv_table + sizeof(struct sysent) * syscall + __builtin_offsetof(struct sysent, sy_call))) = offsets.syscall_cfi_table_jmp_int3;
    }

    for (int i = 0; i < num_syscalls_to_hook_for_ps5; i++)
    {
        int syscall = syscalls_to_hook_for_ps5[i];
        *((uint64_t*)(ps5_sv_table + sizeof(struct sysent) * syscall + __builtin_offsetof(struct sysent, sy_call))) = offsets.syscall_cfi_table_jmp_int3;
    }

    memcpy(shellcore_ps5_sv_table, ps5_sv_table, ps5_sv_table_size);
    for (int i = 0; i < num_extra_syscalls_to_hook_for_shellcore; i++)
    {
        int syscall = extra_syscalls_to_hook_for_shellcore[i];
        *((uint64_t*)(shellcore_ps5_sv_table + sizeof(struct sysent) * syscall + __builtin_offsetof(struct sysent, sy_call))) = offsets.syscall_cfi_table_jmp_int3;
    }

    uint64_t fake_ps4_sv_table = (uint64_t)kmalloc(ps4_sv_table_size);
    uint64_t fake_ps5_sv_table = (uint64_t)kmalloc(ps5_sv_table_size);
    uint64_t fake_shellcore_ps5_sv_table = (uint64_t)kmalloc(ps5_sv_table_size);

    // this locks up if copied in 1 go
    for (int i = 0; i < ps4_sv_table_size; i += 0x1000)
        copyin(fake_ps4_sv_table + i, ps4_sv_table + i, (i + 0x1000 > ps4_sv_table_size) ? (ps4_sv_table_size - i) : 0x1000);

    for (int i = 0; i < ps5_sv_table_size; i += 0x1000)
        copyin(fake_ps5_sv_table + i, ps5_sv_table + i, (i + 0x1000 > ps5_sv_table_size) ? (ps5_sv_table_size - i) : 0x1000);

    for (int i = 0; i < ps5_sv_table_size; i += 0x1000)
        copyin(fake_shellcore_ps5_sv_table + i, shellcore_ps5_sv_table + i, (i + 0x1000 > ps5_sv_table_size) ? (ps5_sv_table_size - i) : 0x1000);

    copyin(offsets.sysentvec_ps4 + sv_table, &fake_ps4_sv_table, 8);
    copyin(offsets.sysentvec + sv_table, &fake_ps5_sv_table, 8);

    char* fake_shellcore_sysentvec = mmap(0, 0x500, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0); // not actual size
    if (fake_shellcore_sysentvec == MAP_FAILED)
        die();

    copyout(fake_shellcore_sysentvec, offsets.sysentvec, 0x500);
    *((uint64_t*)(fake_shellcore_sysentvec + sv_table)) = fake_shellcore_ps5_sv_table;

    uint64_t fake_sysentvec_for_shellcore = (uint64_t)kmalloc(0x500);
    copyin(fake_sysentvec_for_shellcore, fake_shellcore_sysentvec, 0x500);

    int shellcore_pid = find_proc("SceShellCore");
    if (shellcore_pid <= 0)
        die();

    uint64_t shellcore_proc = kernel_get_proc(shellcore_pid);
    if (!shellcore_proc)
        die();

    copyin(shellcore_proc + offsets.p_sysent, &fake_sysentvec_for_shellcore, 8);
#else
    copyin(offsets.sysentvec + 14, &(const uint16_t[1]){0xdeb7}, 2); //native sysentvec
    copyin(offsets.sysentvec_ps4 + 14, &(const uint16_t[1]){0xdeb7}, 2); //ps4 sysentvec
#endif
    copyin(offsets.crypt_singleton_array + 11*8 + 2*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt xts
    copyin(offsets.crypt_singleton_array + 11*8 + 9*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt hmac

    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\npatching shellcore... ", (uintptr_t)27);
    //restore the gdb_stub's SIGTRAP handler
    struct sigaction sa;
    sigaction(SIGBUS, 0, &sa);
    sigaction(SIGTRAP, &sa, 0);

    copyin(IDT+16*9+5, "\x8e", 1);
    copyin(IDT+16*179+5, "\x8e", 1);

    if (shellcore_patches)
    {
        if (patch_shellcore(shellcore_patches,
                            n_shellcore_patches,
                            shellcore_eh_frame_offset))
        {
            notify(shellcore_patch_failure ? shellcore_patch_failure
                                           : "failed to patch shellcore");
        }
    }

    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
#ifndef DEBUG

    const char *console_type = sceKernelIsDevKit() ? "Devkit" : 
                               sceKernelIsTestKit() ? "Testkit" : 
                               "Retail";

    char msg[128];
    snprintf(msg, sizeof(msg), "Welcome To Kstuff Lite 1.12-fpkg-dr-t2\nPlayStation 5 FW: %x.%02x (%s)\nBy sleirsgoevy",
             fwver >> 8, fwver & 0xFF, console_type);
    notify(msg);
	
    return 0;
#endif
    asm volatile("ud2");
    return 0;
}
