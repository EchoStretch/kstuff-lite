#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
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

void* dlsym(void*, const char*);

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
    asm volatile("ud2");
}

#define die() die(__LINE__)

extern uint64_t kdata_base;

void kmemcpy(void* dst, const void* src, size_t sz);

static void kpoke64(void* dst, uint64_t src)
{
    kmemcpy(dst, &src, 8);
}

static void kmemzero(void* dst, size_t sz)
{
    char* umem = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    mlock(umem, sz);
    kmemcpy(dst, umem, sz);
    munmap(umem, sz);
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

static void* kmalloc(size_t sz)
{
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
    // TODO: i dont know when this shifted, may be an earlier fw, also, add this to offsets.c? 
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

void build_uelf_cr3(uint64_t uelf_cr3, void* uelf_base[2], uint64_t uelf_virt_base, uint64_t dmap_virt_base)
{
    static char zeros[4096];
    uint64_t dmap = get_dmap_base();
    uint64_t cr3 = r0gdb_read_cr3();
    uint64_t user_start = (uint64_t)uelf_base[0];
    uint64_t user_end = (uint64_t)uelf_base[1];
    if((uelf_virt_base & 0x1fffff) || (dmap_virt_base & ((1ull << 39) - 1)) || user_end - user_start > 0x200000)
        die();
    uint64_t pml4_virt = uelf_cr3;
    copyin(pml4_virt, zeros, 4096);
    kmemcpy((void*)(pml4_virt+2048), (void*)(dmap+cr3+2048), 2048);
    uint64_t pml3_virt = uelf_cr3 + 4096;
    uint64_t pml3_dmap = uelf_cr3 + 16384; //user-accessible direct mapping of physical memory
    copyin(pml4_virt + 8 * ((uelf_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys(pml3_virt,0,0,0) | 7}, 8);
    copyin(pml4_virt + 8 * ((dmap_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys(pml3_dmap,0,0,0) | 7}, 8);
    copyin(pml3_virt, zeros, 4096);
    uint64_t pml2_virt = uelf_cr3 + 8192;
    copyin(pml3_virt + 8 * ((uelf_virt_base >> 30) & 511), &(uint64_t[1]){virt2phys(pml2_virt,0,0,0) | 7}, 8);
    copyin(pml2_virt, zeros, 4096);
    uint64_t pml1_virt = uelf_cr3 + 12288;
    copyin(pml2_virt + 8 * ((uelf_virt_base >> 21) & 511), &(uint64_t[1]){virt2phys(pml1_virt,0,0,0) | 7}, 8);
    copyin(pml1_virt, zeros, 4096);
    for(uint64_t i = 0; i * 4096 + user_start < user_end; i++)
        copyin(pml1_virt+8*i, &(uint64_t[1]){virt2phys(i*4096+user_start,0,0,0) | 7}, 8);
    for(uint64_t i = 0; i < 512; i++)
        copyin(pml3_dmap+8*i, &(uint64_t[1]){(i<<30) | 135}, 8);
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

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
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
    uint64_t int13_handler;
    copyout(&int13_handler, IDT+16*13, 2);
    copyout((char*)&int13_handler + 2, IDT+16*13+6, 6);
#ifndef FIRMWARE_PORTING
    dbg_enter();
#endif
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"allocating kernel memory... ", (uintptr_t)28);
    for(int i = 0; i < 0x300; i += 2)
        r0gdb_kmalloc(0x100);
    for(int i = 0; i < 2; i += 2)
    {
        while(!mem_blocks[i])
            mem_blocks[i] = r0gdb_kmalloc(1<<23);
        mem_blocks[i+1] = (mem_blocks[i] ? mem_blocks[i] + (1<<23) : 0);
    }
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
    uint64_t shared_area;
    if(comparison_table - comparison_table_base > 4096)
        shared_area = comparison_table - 4096;
    else
        shared_area = comparison_table + 65536;
    kmemzero((void*)shared_area, 4096);
    uint64_t uelf_virt_base = (find_empty_pml4_index(0) << 39) | (-1ull << 48);
    uint64_t dmem_virt_base = (find_empty_pml4_index(1) << 39) | (-1ull << 48);
    shared_area = virt2phys(shared_area,0,0,0) + dmem_virt_base;

    volatile int zero = 0; //hack to force runtime calculation of string pointers
    const char* symbols[] = {
        "comparison_table"+zero,
        "dmem"+zero,
        "int1_handler"+zero,
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
#define OFFSET(x) (#x)+zero,
#include "../prosper0gdb/offsets/offset_list.txt"
#undef OFFSET
        0,
    };
	
    uint64_t fwver = r0gdb_get_fw_version() >> 16;
    uint64_t values[] = {
        comparison_table,      // comparison_table
        dmem_virt_base,        // dmem
        int1_handler,          // int1_handler
        int13_handler,         // int13_handler
        0x1237,                // .ist_errc
        0x1238,                // .ist_noerrc
        0x1239,                // .ist4
        0x1234,                // .pcpu
        shared_area,           // shared_area
        0x123a,                // .tss
        0x1235,                // .uelf_cr3
        0x1236,                // .uelf_entry
        fwver,                 // .fwver
#define OFFSET(x) offsets.x,
#include "../prosper0gdb/offsets/offset_list.txt"
#undef OFFSET
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
        values[ist_errc_idx] = TSS(cpu)+28+3*8;
        values[ist_noerrc_idx] = TSS(cpu)+28+7*8;
        values[ist4_idx] = percpu_ist4[cpu];
        values[tss_idx] = TSS(cpu);
        void* uelf_entry = 0;
        void* uelf_base[2] = {0};
        char* uelf = load_kelf(uek, symbols, values, uelf_base, &uelf_entry, uelf_virt_base);
        uintptr_t uelf_cr3 = (uintptr_t)kmalloc(24576);
        uelf_cr3 = ((uelf_cr3 + 4095) | 4095) - 4095;
        uelf_cr3s[cpu] = uelf_cr3;
        values[uelf_cr3_idx] = virt2phys(uelf_cr3,0,0,0);
        values[uelf_entry_idx] = (uintptr_t)uelf_entry - (uintptr_t)uelf_base[0] + uelf_virt_base;
        void* entry = 0;
        void* base[2] = {0};
        char* kelf = load_kelf(kek, symbols, values, base, &entry, 0);
        build_uelf_cr3(uelf_cr3, uelf_base, uelf_virt_base, dmem_virt_base);
        uelf_bases[cpu] = (uintptr_t)uelf;
        kelf_bases[cpu] = (uint64_t)kelf;
        kelf_entries[cpu] = (uint64_t)entry;
    }
    r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) | 0x100);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done loading\npatching idt... ", (uintptr_t)29);
    uint64_t cr3 = r0gdb_read_cr3();
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        uint64_t entry = kelf_entries[cpu];
        kmemcpy((char*)IDT+16*13, (char*)entry, 2);
        kmemcpy((char*)IDT+16*13+6, (char*)entry+2, 6);
        kmemcpy((char*)IDT+16*13+4, "\x03", 1);
        kmemcpy((char*)IDT+16*1, (char*)entry+16, 2);
        kmemcpy((char*)IDT+16*1+6, (char*)entry+18, 6);
        kmemcpy((char*)IDT+16*1+4, "\x07", 1);
        kmemcpy((char*)TSS(cpu)+28+3*8, (char*)entry+8, 8);
        kmemcpy((char*)TSS(cpu)+28+7*8, (char*)entry+24, 8);
    }
    uint64_t iret = offsets.doreti_iret;
    kmemcpy((char*)(IDT+16*2), (char*)&iret, 2);
    kmemcpy((char*)(IDT+16*2+6), (char*)&iret+2, 6);
    //kmemzero((char*)(IDT+16*1), 16);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\napplying kdata patches... ", (uintptr_t)31);
    copyin(offsets.sysentvec + 14, &(const uint16_t[1]){0xdeb7}, 2); //native sysentvec
    copyin(offsets.sysentvec_ps4 + 14, &(const uint16_t[1]){0xdeb7}, 2); //ps4 sysentvec
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
            notify("failed to patch shellcore");
        }
    }

    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    #ifndef DEBUG
    //notify("ps5-kstuff successfully loaded");

    // Extract BCD parts
    int major_bcd = (fwver >> 8) & 0xFF;   // major version in BCD
    int minor_bcd = fwver & 0xFF;          // minor version in BCD

    // Convert BCD → decimal
    int major = (major_bcd >> 4) * 10 + (major_bcd & 0xF);
    int minor_dec = (minor_bcd >> 4) * 10 + (minor_bcd & 0xF);

    char msg[64], *p = msg;

    // Header
    const char *hdr =
        "Welcome To Kstuff Lite 1.0\nPlayStation 5 FW: ";
    while (*hdr) *p++ = *hdr++;

    // Major
    if (major >= 10)
        *p++ = '0' + major / 10;
    *p++ = '0' + major % 10;

    // Minor
    *p++ = '.';
    *p++ = '0' + minor_dec / 10;
    *p++ = '0' + minor_dec % 10;

    *p++ = ' ';

    const char *t;

    if (sceKernelIsDevKit())
        t = "(Devkit)";
    else if (sceKernelIsTestKit())
        t = "(Testkit)";
    else
        t = "(Retail)";

    while (*t)
        *p++ = *t++;

    // Footer
    const char *ftr = "\nBy sleirsgoevy";
    while (*ftr) *p++ = *ftr++;

    *p = 0;
    notify(msg);
	
    return 0;
#endif
    asm volatile("ud2");
    return 0;
}
