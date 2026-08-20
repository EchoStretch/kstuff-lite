#define sysctl __sysctl
#include "../gdb_stub/dbg.h"
#include "../gdb_stub/trap_state.h"
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/cpuset.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <machine/sysarch.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include "r0gdb.h"
#include "offsets.h"

#ifndef PS5KEK

#define gettid() (*((int*(*)(void))dlsym((void*)0x1, "pthread_self"))())
#define WRAPPER2(name, sym) ((typeof(&name))dlsym((void*)0x1, #sym))
#define WRAPPER(name) WRAPPER2(name, name)

#else

static inline int gettid(void)
{
    long tid;
    thr_self(&tid);
    return tid;
}

#define WRAPPER(name) ({ void* ans; asm volatile("lea " #name "(%%rip), %0":"=r"(ans)); ans; })
#define WRAPPER2(name, sym) WRAPPER(name)

#endif

//#define CPU_2 //TODO: run on any cpu

static int master_fd;
static int victim_fd;
static uintptr_t victim_pktopts;
uintptr_t kdata_base;

void	*memcpy(void * __restrict, const void * __restrict, size_t);
void	*memset(void *, int, size_t);

static inline int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    for (size_t i = 0; i < n; i++)
    {
        if (p1[i] != p2[i])
        {
            return (int)p1[i] - (int)p2[i];
        }
    }
    return 0;
}

static inline void cpu_relax(void)
{
    asm volatile("pause");
}

static void* malloc(size_t size)
{
    return mmap(0, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t kread8(uint64_t ptr)
{
    uint64_t offset = 0;
    if(ptr % 4096 >= 4076)
    {
        offset = ptr % 4096 - 4076;
        if(offset >= 12)
            offset = 12;
    }
    else if(ptr % 256 == 255)
        offset = 1;
    char buf[20] = {0};
    *(uint64_t*)buf = ptr - offset;
    setsockopt(master_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
    socklen_t l = 20;
    getsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, &l);
    return *(uint64_t*)(buf + offset);
}

int kwrite20(uint64_t ptr, uint64_t a, uint64_t b, uint32_t c)
{
    char buf[20] = {0};
    *(uint64_t*)buf = ptr;
    setsockopt(master_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
    *(uint64_t*)buf = a;
    *(uint64_t*)(buf + 8) = b;
    *(uint32_t*)(buf + 16) = c;
    return setsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
}

static int set_rthdr_size(int sock, int size)
{
    int len = ((size / 8) - 1) & ~1;
    int sz = (len + 1) * 8;
    char buf[2048] = {0};
    buf[1] = len;
    buf[3] = len / 2;
    return setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, buf, sz);
}

uint64_t kmalloc(int sz)
{
    if(sz > 2048)
        return 0;
    if(sz < 32)
        sz = 32;
    kwrite20(victim_pktopts+112, 0, 1, 0);
    kwrite20(victim_pktopts+120, 0, 1, 0);
    set_rthdr_size(victim_fd, sz);
    uint64_t addr = kread8(victim_pktopts+112);
    kwrite20(victim_pktopts+112, 0, 1, 0);
    kwrite20(victim_pktopts+120, 0, 1, 0);
    return addr;
}

int kfree(uint64_t ptr)
{
    kwrite20(victim_pktopts+112, ptr, 0, 0);
    return setsockopt(victim_fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
}

static int the_pipe[2];
uint64_t proc;
uint64_t ofiles;
uint64_t rpipe;

static void init_pipe(void)
{
    pipe(the_pipe);
    proc = kread8(offsets.allproc);
    while(proc && (int)kread8(proc+0xbc) != getpid())
        proc = kread8(proc);
    if(!proc)
        *(void* volatile*)0;
    ofiles = kread8(kread8(proc+0x48));
    rpipe = kread8(kread8(ofiles+8+48*the_pipe[0]));
}

ssize_t copyout(void* dst, uint64_t src, size_t count)
{
    if(kwrite20(rpipe, 0x4000000040000000, 0x4000000000000000, 0))
        *(void* volatile*)0;
    if(kwrite20(rpipe+15, (src<<8)|0x40, src>>56, 0))
        *(void* volatile*)0;
    getpid(); //leaks td_retval offset
    volatile double x = 1; //makes sure PCB_FPUINITDONE is set
    x += 1;
    return read(the_pipe[0], dst, count);
}

ssize_t copyin(uint64_t dst, const void* src, size_t count)
{
    if(kwrite20(rpipe, 0, 0x4000000000000000, 0))
        *(void* volatile*)0;
    if(kwrite20(rpipe+15, (dst<<8)|0x40, dst>>56, 0))
        *(void* volatile*)0;
    return write(the_pipe[1], src, count);
}

void* dlsym(void*, const char*);

static uint64_t get_thread(void)
{
    int tid = gettid();
    for(uint64_t thr = kread8(proc+16); thr; thr = kread8(thr+16))
        if((int)kread8(thr+0x9c) == tid)
            return thr;
    return 0;
}

static const void* memmem(const void* a, size_t sz1, const void* b, size_t sz2)
{
    for(size_t i = 0; i + sz2 <= sz1; i++)
    {
        int ok = 1;
        const char* p1 = a;
        p1 += i;
        const char* p2 = b;
        for(size_t j = 0; j < sz2 && ok; j++)
            if(p1[j] != p2[j])
                ok = 0;
        if(ok)
            return p1;
    }
    return 0;
}

static void bind_to_all_available_cpus(void)
{
    for(int i = 0; i < 128; i++)
    {
        uint8_t affinity[16] = {0};
        cpuset_getaffinity(3, 1, gettid(), 16, (void*)affinity);
        affinity[i / 8] |= 1 << (i % 8);
        cpuset_setaffinity(3, 1, gettid(), 16, (void*)affinity);
    }
}

static int bind_to_some_cpu(int skip)
{
    uint8_t affinity[16] = {0};
    cpuset_getaffinity(3, 1, gettid(), 16, (void*)affinity);
    int i = 0;
    while(i < 16 && !affinity[i])
        i++;
    for(int j = 0; j < skip; j++)
    {
        affinity[i] &= ~(affinity[i] ^ (affinity[i] - 1));
        while(i < 16 && !affinity[i])
            i++;
    }
    if(i == 16)
        return -1;
    affinity[i] &= (affinity[i] ^ (affinity[i] - 1));
    i++;
    while(i < 16)
        affinity[i++] = 0;
    return cpuset_setaffinity(3, 1, gettid(), 16, (void*)affinity);
}

__attribute__((optimize(3)))
static void* hammer_thread(uint64_t* arg)
{
    if(bind_to_some_cpu(3))
        kill(getpid(), SIGKILL);
    volatile uint64_t* target = (volatile uint64_t*)arg[0];
    uint64_t stack = arg[1];
    for(;;)
    {
        if(target[0] == 0x20)
        {
            ((volatile uint32_t*)target)[-1] = 16;
            target[0] = 0x43;
            target[1] = 0x202;
            target[2] = stack;
            target[3] = 0x3b;
        }
    }
}

static void jmp_setcontext(uint64_t pc)
{
    uint64_t data[0x4c0/8];
    getcontext((void*)data);
    data[0xe0/8] = pc;
    setcontext((void*)data);
}

static int* cpuid(int which, int* out)
{
    asm volatile("cpuid":"=a"(out[0]),"=c"(out[1]),"=d"(out[2]),"=b"(out[3]):"a"(which));
    return out;
}

static int set_sigaltstack(void)
{
    stack_t stk = {
        .ss_sp = malloc(65536),
        .ss_size = 65536,
        .ss_flags = 0
    };
    if(sigaltstack(&stk, 0))
        return -1;
    for(int i = 1; i < 32; i++)
    {
        struct sigaction sa;
        if(sigaction(i, 0, &sa))
            return -1;
        sa.sa_flags |= SA_ONSTACK;
        if(sigaction(i, &sa, 0))
            return -1;
    }
    return 0;
}

static void getpid_for_smsw_ax(void)
{
    volatile double x = 1;
    x += 1;
    getpid();
}

extern int in_signal_handler;
int gdbstub_main_loop(struct trap_state* ts, ssize_t* result, int* ern);
void run_in_kernel(struct regs*);

uint64_t kstack;
uint64_t kframe;
uint64_t uretframe;
uint64_t iret;

static int init_run = 0;
static int idt6_patched = 0;
static char og_idt1[16];
static char og_idt6[16];
static char og_idt9[16];
static char og_idt179[16];
static uint64_t og_tss[16][3];

extern char _start[];
extern char _end[];

void r0gdb_setup(int do_swapgs)
{
    if(init_run)
        return;
    //mlock all our code & data
    mlock(_start, _end-_start);
    for(size_t i = 0; i < _end-_start; i += 4096)
        *(volatile char*)(_start+i);
#ifdef CPU_2
    //pin ourselves to cpu 2 (13 in apic order)
    char affinity[16] = {4};
    cpuset_setaffinity(3, 1, gettid(), 16, (void*)affinity);
#endif
    //resolve addresses
    iret = offsets.doreti_iret;
    volatile uint64_t add_rsp_0xe8_iret = offsets.add_rsp_iret;
    volatile uint64_t swapgs_add_rsp_0xe8_iret = offsets.swapgs_add_rsp_iret;
    //set up alternative stacks on all cpus
    uint64_t gadget_stack = kmalloc(2048);
#ifdef CPU_2
    int cpu = 13;
#else
    for(int cpu = 0; cpu < 16; cpu++)
#endif
    {
        uint64_t tss_for_cpu = offsets.tss_array + cpu * 0x68;
        char utss[0x68];
        copyout(utss, tss_for_cpu, 0x68);
        og_tss[cpu][0] = *(volatile uint64_t*)(utss+0x34);
        og_tss[cpu][1] = *(volatile uint64_t*)(utss+0x3c);
        og_tss[cpu][2] = *(volatile uint64_t*)(utss+0x4c);
        if(cpu == 13)
            kstack = *(volatile uint64_t*)(utss+0x3c) - 0x28;
        *(volatile uint64_t*)(utss+0x34) = gadget_stack + 0xe0;
        *(volatile uint64_t*)(utss+0x3c) = gadget_stack + 0x1f0;
        *(volatile uint64_t*)(utss+0x4c) = gadget_stack + 0x440;
        copyin(tss_for_cpu, utss, 0x68);
    }
    uint64_t tframe = gadget_stack + 0x1a0;
    kframe = gadget_stack + 0x1c8;
    uretframe = gadget_stack + 0x2b0;
    //set up trampoline frame
    kwrite20(tframe, iret, 0x20, 0);
    kwrite20(tframe+16, 2, kframe, 0);
    //set up int179 frames
#ifdef MEMRW_FALLBACK
    if(!offsets.rep_movsb_pop_rbp_ret)
    {
        kwrite20(gadget_stack+0x500, iret, 0x20, 0);
        kwrite20(gadget_stack+0x510, 0x40002, gadget_stack+0x418, 0);
    }
    else
#endif
    {
        kwrite20(gadget_stack+0x408, 0, iret, 0);
        kwrite20(gadget_stack+0x500, offsets.rep_movsb_pop_rbp_ret, 0x20, 0);
        kwrite20(gadget_stack+0x510, 0x40002, gadget_stack+0x408, 0);
    }
    //set up gates
    volatile char* addr = do_swapgs ? (void*)&swapgs_add_rsp_0xe8_iret : (void*)&add_rsp_0xe8_iret;
    char gate[16] = {0};
    gate[0] = addr[0];
    gate[1] = addr[1];
    gate[2] = 0x20;
    gate[4] = 4;
    gate[5] = 0x8e;
    gate[6] = addr[2];
    gate[7] = addr[3];
    gate[8] = addr[4];
    gate[9] = addr[5];
    gate[10] = addr[6];
    gate[11] = addr[7];
    copyout(og_idt1, offsets.idt+1*16, 16);
    copyout(og_idt9, offsets.idt+9*16, 16);
    copyout(og_idt179, offsets.idt+179*16, 16);
    copyin(offsets.idt+1*16, gate, 16);
    if(do_swapgs == 2)
    {
        copyout(og_idt6, offsets.idt+6*16, 16);
        copyin(offsets.idt+6*16, gate, 16);
        idt6_patched = 1;
    }
    gate[4] = 3;
    gate[5] = 0xee;
    copyin(offsets.idt+9*16, gate, 16);
    gate[4] = 6;
    copyin(offsets.idt+179*16, gate, 16);
    init_run = 1;
}

void r0gdb_cleanup(void)
{
    if (!init_run)
        return;
    r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) | 0x100);

#ifdef CPU_2
    int cpu = 13;
#else
    for(int cpu = 0; cpu < 16; cpu++)
#endif
    {
        uint64_t tss_for_cpu = offsets.tss_array + cpu * 0x68;
        char utss[0x68];
        copyout(utss, tss_for_cpu, 0x68);
        *(volatile uint64_t*)(utss+0x34) = og_tss[cpu][0];
        *(volatile uint64_t*)(utss+0x3c) = og_tss[cpu][1];
        *(volatile uint64_t*)(utss+0x4c) = og_tss[cpu][2];
        copyin(tss_for_cpu, utss, 0x68);
    }

    copyin(offsets.idt+1*16, og_idt1, 16);
    if(idt6_patched)
        copyin(offsets.idt+6*16, og_idt6, 16);
    copyin(offsets.idt+9*16, og_idt9, 16);
    copyin(offsets.idt+179*16, og_idt179, 16);
}

void r0gdb_exit(void)
{
    //no-op, checked by comparing rip
}

static void r0gdb_loop(void)
{
    struct trap_state ts = {0};
    ts.trap_signal = SIGTRAP;
    ts.regs.rsp = kstack;
    ts.regs.eflags = 0x102;
    for(;;)
    {
        while(__atomic_exchange_n(&in_signal_handler, 1, __ATOMIC_ACQUIRE))
            cpu_relax();
        gdbstub_main_loop(&ts, 0, 0);
        __atomic_exchange_n(&in_signal_handler, 0, __ATOMIC_RELEASE);
        ts.regs.eflags &= ~0x200;
        ts.regs.eflags |= 0x102;
        if((void*)ts.regs.rip == (void*)r0gdb_exit)
            break;
        run_in_kernel(&ts.regs);
    }
}

void r0gdb(void)
{
    r0gdb_setup(1);
    r0gdb_loop();
}

uint64_t r0gdb_rdmsr(uint32_t ecx)
{
    struct regs regs = {0};
    regs.rip = offsets.rdmsr_start;
    regs.rsp = kstack;
    regs.rcx = ecx;
    regs.eflags = 0x102;
    run_in_kernel(&regs);
    return regs.rdx << 32 | regs.rax;
}

void r0gdb_wrmsr(uint32_t ecx, uint64_t value)
{
    struct regs regs = {0};
    regs.rip = offsets.wrmsr_ret;
    regs.rsp = kstack;
    regs.rcx = ecx;
    regs.rax = value;
    regs.rdx = value >> 32;
    regs.eflags = 0x102;
    run_in_kernel(&regs);
}

void r0gdb_read_dbregs(uint64_t* out)
{
    struct regs regs = {0};
    regs.rip = offsets.dr2gpr_start;
    regs.rsp = kstack;
    regs.eflags = 0x102;
    for(int i = 0; i < 6; i++)
        run_in_kernel(&regs);
    out[0] = regs.r15;
    out[1] = regs.r14;
    out[2] = regs.r13;
    out[3] = regs.r12;
    out[4] = regs.r11;
    out[5] = regs.rax;
}

uint64_t r0gdb_read_dbreg(int which)
{
    which &= 7;
    if(which >= 6)
        which -= 2;
    uint64_t regs[6];
    r0gdb_read_dbregs(regs);
    return regs[which];
}

void r0gdb_write_dbregs(uint64_t* inp)
{
    struct regs regs = {0};
    regs.rip = offsets.gpr2dr_1_start;
    regs.rsp = kstack;
    regs.eflags = 0x102;
    regs.r15 = inp[0];
    regs.r14 = inp[1];
    regs.r13 = inp[2];
    regs.rbx = inp[3];
    regs.r11 = inp[4];
    regs.rcx = inp[5];
    regs.rax = inp[5];
    for(int i = 0; i < 9; i++)
        run_in_kernel(&regs);
    regs.r11 = inp[4];
    regs.r15 = inp[5];
    regs.rip = offsets.gpr2dr_2_start;
    for(int i = 0; i < 3; i++)
        run_in_kernel(&regs);
}

void r0gdb_write_dbreg(int which, uint64_t value)
{
    which &= 7;
    if(which >= 6)
        which -= 2;
    uint64_t regs[6];
    r0gdb_read_dbregs(regs);
    regs[which] = value;
    r0gdb_write_dbregs(regs);
}

uint64_t r0gdb_read_cr3(void)
{
    struct regs regs = {0};
    regs.rip = offsets.mov_rax_cr3;
    regs.rsp = kstack;
    regs.eflags = 0x102;
    run_in_kernel(&regs);
    return regs.rax;
}

void r0gdb_write_cr3(uint64_t cr3)
{
    struct regs regs = {0};
    regs.rip = offsets.mov_cr3_rax_mov_ds;
    regs.rsp = kstack;
    regs.eflags = 0x102;
    regs.rax = cr3;
    run_in_kernel(&regs);
}

uint64_t trace_frame_size = 168;
uint64_t trace_base;
uint64_t trace_start;
uint64_t trace_end;
void(*trace_prog)(uint64_t*);
extern char ret2trace[];
static uint64_t uretframe_for_trace[5];
static int trace_ready;

int r0gdb_trace(size_t trace_size)
{
    static int tracing;
    if(!tracing)
    {
        r0gdb_setup(0);
        bind_to_some_cpu(0);
        r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) & -0x101);
        char* stack = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if(stack == MAP_FAILED)
            goto fail_trace_setup;
        stack[0] = 1;
        if(mlock(stack, 16384))
        {
            munmap(stack, 16384);
            goto fail_trace_setup;
        }
        /*uint64_t urf[5] = {(uintptr_t)ret2trace, 0x43, 2, (uintptr_t)stack+16384, 0x3b};
        copyin(uretframe, urf, sizeof(urf));*/
        uretframe_for_trace[0] = (uintptr_t)ret2trace;
        uretframe_for_trace[1] = 0x43;
        uretframe_for_trace[2] = 2;
        uretframe_for_trace[3] = (uintptr_t)stack + 16384;
        uretframe_for_trace[4] = 0x3b;
        if(copyin(uretframe, uretframe_for_trace, sizeof(uretframe_for_trace)) != sizeof(uretframe_for_trace))
        {
            munmap(stack, 16384);
            goto fail_trace_setup;
        }
        tracing = 1;
        trace_ready = 1;
    }
    char* tracebuf = 0;
    if(trace_size)
    {
        tracebuf = mmap(0, trace_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if(tracebuf == MAP_FAILED)
        {
            trace_base = 0;
            trace_start = 0;
            trace_end = 0;
            return -1;
        }
    }
    for(size_t i = 0; i < trace_size; i += 4096)
        tracebuf[i] = 0;
    if(trace_size && mlock(tracebuf, trace_size))
    {
        munmap(tracebuf, trace_size);
        trace_base = 0;
        trace_start = 0;
        trace_end = 0;
        return -1;
    }
    trace_base = (uint64_t)tracebuf;
    trace_start = trace_base;
    trace_end = trace_base + trace_size;
    return 0;

fail_trace_setup:
    trace_ready = 0;
    uretframe_for_trace[0] = 0;
    trace_base = 0;
    trace_start = 0;
    trace_end = 0;
    return -1;
}

void r0gdb_trace_reset(void)
{
    trace_start = trace_base;
}

int r0gdb_open_socket(const char* ipaddr, int port)
{
    uint32_t ip = 0;
    int shift = 0;
    for(int i = 0; i < 4; i++)
    {
        int q = 0;
        while(*ipaddr >= '0' && *ipaddr <= '9')
            q = 10 * q + (*ipaddr++) - '0';
        ipaddr++;
        ip |= q << shift;
        shift += 8;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        return -1;
    int one = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in conn = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = ip },
        .sin_port = port >> 8 | port << 8,
    };
    if(connect(sock, (void*)&conn, sizeof(conn)))
    {
        close(sock);
        return -1;
    }
    return sock;
}

int r0gdb_sendall(int sock, const void* data, size_t sz)
{
    const char* p = (const char*)data;
    while(sz)
    {
        ssize_t chk = write(sock, p, sz);
        if(chk < 0 && errno == EINTR)
            continue;
        if(chk <= 0)
            return -1;
        p += chk;
        sz -= chk;
    }
    return 0;
}

int r0gdb_sendfile(int fd1, int fd2)
{
    char buf[4096];
    ssize_t chk;
    while((chk = read(fd1, buf, sizeof(buf))) > 0)
    {
        ssize_t chk2;
        size_t offset = 0;
        while((chk2 = write(fd2, buf+offset, chk-offset)) > 0)
            offset += chk2;
        if(offset != chk)
            return -1;
    }
    return chk < 0 ? -1 : 0;
}

int r0gdb_trace_send(const char* ipaddr, int port)
{
    int sock = r0gdb_open_socket(ipaddr, port);
    if(sock < 0)
        return -1;
    int ans = r0gdb_sendall(sock, (void*)trace_base, trace_start - trace_base);
    close(sock);
    return ans;
}

static void clear_tf(int sig, siginfo_t* s, void* o_uc)
{
    ucontext_t* uc = (ucontext_t*)o_uc;
    mcontext_t* mc = (mcontext_t*)(((char*)&uc->uc_mcontext)+48); // wtf??
    mc->mc_rflags &= -257;
}

int r0gdb_instrument(size_t size)
{
    static int instrumented = 0;
    if(instrumented)
        return 0;
    if(r0gdb_trace(size))
        return -1;
    struct sigaction sa = {
        .sa_sigaction = clear_tf,
        .sa_flags = SA_SIGINFO
    };
    sigaction(SIGTRAP, &sa, 0);
    instrumented = 1;
    return 0;
}

void kmemcpy(void* dst, const void* src, size_t sz);

static int set_trace(void)
{
    if(!trace_ready || !uretframe_for_trace[0])
        return -1;
    kmemcpy((void*)uretframe, uretframe_for_trace, sizeof(uretframe_for_trace));
    uint64_t q;
    asm volatile("pop %0\npushfq\norb $1, 1(%%rsp)\npopfq\npush %0":"=r"(q));
    return 0;
}

/*static int count = 0;

static void eat_count(uint64_t* regs)
{
    if(count == 0)
        regs[2] &= -257;
    count--;
}*/

static void untrace_fn(uint64_t* regs)
{
    uint64_t rsp = regs[3];
    uint64_t ret_gadget = offsets.nop_ret;
    uint64_t frame[6] = {iret, ret_gadget, 0x20, regs[2], rsp, 0};
    rsp -= 0x30;
    kmemcpy((void*)rsp, frame, 48);
    regs[3] = rsp;
    regs[2] &= -257;
}

#define SKIP_SCHEDULER\
    if(regs[0] == offsets.cpu_switch)\
    {\
        untrace_fn(regs);\
        return;\
    }

static void* trace_prog_after_trace_on_break;

static void trace_on_break(uint64_t* regs)
{
    SKIP_SCHEDULER
    static uint64_t lr;
    if(!(regs[2] & 256))
    {
        regs[2] |= 256;
        kmemcpy(&lr, (void*)regs[3], 8);
    }
    else if(regs[0] == lr)
    {
        regs[2] &= -257;
        if(trace_prog_after_trace_on_break)
            trace_prog = trace_prog_after_trace_on_break;
    }
}

static uint64_t ptr_to_leaked_rep_movsq;
static void leak_rep_movsq(uint64_t* regs)
{
    static int not_first;
    static int leaking = 0;
    static uint64_t old_rdi, old_rsi, old_rcx;
    if(not_first)
    {
        if(leaking == 1)
        {
            regs[12] = old_rdi;
            regs[11] = old_rsi;
            regs[6] = old_rcx;
            leaking = 2;
        }
        else if(!leaking && regs[12] == old_rdi + 8 && regs[11] == old_rsi + 8 && regs[6] == old_rcx - 1 && regs[6])
        {
            old_rdi = regs[12];
            old_rsi = regs[11];
            old_rcx = regs[6];
            regs[12] = ptr_to_leaked_rep_movsq;
            regs[11] = kframe;
            regs[6] = 2;
            leaking = 1;
            return;
        }
    }
    not_first = 1;
    old_rdi = regs[12];
    old_rsi = regs[11];
    old_rcx = regs[6];
}

static uint64_t* jprog = 0;

static void do_jprog(uint64_t* regs)
{
    SKIP_SCHEDULER
    uint64_t rip = regs[0];
    for(int i = 0; jprog[i]; i += 3)
        if(rip == jprog[i])
        {
            if(jprog[i+1] < 21)
                regs[jprog[i+1]] = jprog[i+2];
            else if(jprog[i+1] == 21)
            {
                uint64_t lr;
                kmemcpy(&lr, (void*)regs[3], 8);
                regs[0] = lr;
                regs[3] += 8;
                regs[5] = jprog[i+2];
            }
            else if(jprog[i+1] == 22)
                trace_prog = (void*)jprog[i+2];
        }
}

static uint64_t* call_trace_base;
static uint64_t* call_trace_start;
static uint64_t* call_trace_end;
static int call_trace_untrace_on_unaligned = 0;

static void trace_skip_scheduler_only(uint64_t* regs)
{
    SKIP_SCHEDULER
}

static void trace_calls(uint64_t* regs)
{
    static uint64_t prev_rip = 0;
    static uint64_t prev_rsp = 0;
    SKIP_SCHEDULER
    int call = 0;
    if(regs[0] - prev_rip >= 16)
    {
        if(regs[3] == prev_rsp - 8)
        {
            call = 1;
            if(prev_rsp % 16 && call_trace_untrace_on_unaligned)
                regs[2] &= -257;
        }
        else if(regs[3] == prev_rsp + 8)
            call = 2;
    }
    if(call)
    {
        uint64_t frame[3];
        if(call == 1)
        {
            frame[0] = prev_rip;
            frame[1] = regs[0];
            frame[2] = regs[3];
        }
        else if(call == 2)
        {
            frame[0] = regs[0];
            frame[1] = 0;
            frame[2] = prev_rsp;
        }
        if(call_trace_end - call_trace_start >= 3)
        {
            *call_trace_start++ = frame[0];
            *call_trace_start++ = frame[1];
            *call_trace_start++ = frame[2];
        }
    }
    prev_rip = regs[0];
    prev_rsp = regs[3];
}

static void start_call_trace(void)
{
    call_trace_base = (uint64_t*)trace_base;
    call_trace_start = (uint64_t*)trace_start;
    call_trace_end = (uint64_t*)trace_end;
    trace_base = trace_start = trace_end = 0;
    trace_prog = trace_calls;
}

static void end_call_trace(void)
{
    trace_base = (uint64_t)call_trace_base;
    trace_start = (uint64_t)call_trace_start;
    trace_end = (uint64_t)call_trace_end;
    call_trace_base = call_trace_start = call_trace_end = 0;
}

static void fix_mprotect(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == offsets.mprotect_fix_start)
        regs[0] = offsets.mprotect_fix_end;
}

int mprotect20(void* addr, size_t sz, int prot)
{
    if(r0gdb_instrument(0))
        return -1;
    int(*p_mprotect)(void*, size_t, int) = WRAPPER(mprotect);
    trace_prog = fix_mprotect;
    if(set_trace())
    {
        trace_prog = 0;
        return -1;
    }
    int ans = p_mprotect(addr, sz, prot);
    trace_prog = 0;
    return ans;
}

static uint64_t sys_write;
static uint64_t sys_sigaction;
static uint64_t sys_getpid;

static uint64_t dumped_auth_info[17];
static int authinfo_dumped = 0;

static void filter_dump_authinfo(uint64_t* regs)
{
    static uint64_t lr;
    static uint64_t r8;
    SKIP_SCHEDULER
    if(regs[0] == offsets.sceSblAuthMgrSmIsLoadable2)
    {
        kmemcpy(&lr, (void*)regs[3], 8);
        r8 = regs[13];
    }
    else if(regs[0] == lr)
    {
        lr = 0;
        kmemcpy(dumped_auth_info, (void*)r8, sizeof(dumped_auth_info));
        authinfo_dumped = 1;
    }
}

static uint64_t fncall_fn = 0;
static uint64_t fncall_args[6];
static uint64_t fncall_ans = 0;
static int fncall_no_untrace = 0;

static void getpid_to_fncall(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == sys_getpid)
    {
        regs[0] = fncall_fn;
        regs[12] = fncall_args[0];
        regs[11] = fncall_args[1];
        regs[7] = fncall_args[2];
        regs[6] = fncall_args[3];
        regs[13] = fncall_args[4];
        regs[14] = fncall_args[5];
        if(fncall_no_untrace)
        {
            regs[3] -= 8;
            kmemcpy((void*)regs[3], &regs[0], 8);
            regs[0] = offsets.nop_ret;
        }
        else
            untrace_fn(regs);
    }
    else if(regs[0] == offsets.syscall_after)
    {
        fncall_ans = regs[5];
        regs[5] = 0;
        regs[2] &= -257;
    }
}

uint64_t r0gdb_kfncall(uint64_t fn, ...)
{
    va_list args;
    va_start(args, fn);
    for(int i = 0; i < 6; i++)
        fncall_args[i] = va_arg(args, uint64_t);
    va_end(args);
    fncall_fn = fn;
    if(r0gdb_instrument(0))
        return 0;
    void(*p_getpid)(void) = WRAPPER(getpid);
    trace_prog = getpid_to_fncall;
    if(!sys_getpid)
        kmemcpy(&sys_getpid, (void*)(offsets.sysents + 48*SYS_getpid + 8), 8);
    if(set_trace())
    {
        trace_prog = 0;
        return 0;
    }
    p_getpid();
    return fncall_ans;
}

uint64_t r0gdb_kmalloc(size_t sz)
{
    //return r0gdb_kfncall(offsets.malloc, sz, offsets.M_something, 2 /* M_WAITOK */);
    return r0gdb_kfncall(offsets.malloc, sz, offsets.M_something, 1 /* M_NOWAIT */);
}

static uint64_t instr_start;
static uint64_t instr_jump;
static int instrs_left;

static void instr_count(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(!(regs[2] & 256))
    {
        regs[2] |= 256;
        instrs_left = 100;
    }
    if(regs[0] == instr_start)
    {
        regs[0] = instr_jump;
        instr_start = 0;
    }
    else if(!instr_start)
    {
        if(!instrs_left)
            regs[2] &= -257;
        else
            instrs_left--;
    }
}

static void instr_count_and_hang(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(!instrs_left)
    {
        if(regs[1] == 0x20 && (regs[2] & 512))
        {
            regs[0] = iret;
            regs[2] &= -257ull;
            regs[3] -= 40;
            kmemcpy((void*)regs[3], regs, 40);
        }
    }
    else
        instrs_left--;
}

static int count_instrs(void(*fn)(uint64_t, uint64_t, uint64_t), uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t entry, uint64_t jump, int instrs)
{
    r0gdb_trace_reset();
    trace_prog = instr_count;
    instr_start = entry;
    instr_jump = jump ? jump : entry;
    instrs_left = instrs;
    if(set_trace())
        return -1;
    fn(arg1, arg2, arg3);
    return (trace_start-trace_base)/168;
}

static uint64_t get_last_pc(void)
{
    return ((uint64_t*)trace_start)[-21];
}

static uint64_t get_last_unique(void)
{
    uint64_t* start = (uint64_t*)trace_base;
    uint64_t* end = (uint64_t*)trace_start;
    uint64_t ans = start[0];
    for(uint64_t* i = start; i < end; i += 21)
    {
        uint64_t cur = i[0];
        for(uint64_t* j = start; j < i; j += 21)
            if(cur == j[0])
            {
                cur = ans;
                break;
            }
        ans = cur;
    }
    return ans;
}

static void filter_sm_service(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == offsets.sceSblServiceMailbox)
    {
        kmemcpy(regs+15, (void*)regs[3], 8);
        instrs_left = 100000;
    }
    if(instrs_left)
        instrs_left--;
    else
        trace_start -= trace_frame_size;
}

#if 0
static void filter_sm_calls(uint64_t* regs)
{
    static int inside = 0;
    static uint64_t limit = 0;
    SKIP_SCHEDULER
    if(inside && regs[0] == limit)
    {
        inside = 0;
        limit = 0;
    }
    if(/*regs[0] == kdata_base - 0x8a5a40 //verifyHeader
    || regs[0] == kdata_base - 0x8a5c40 //sceSblAuthMgrSmIsLoadable2
    || regs[0] == kdata_base - 0x8a5780 //loadSelfSegment
    ||*/ regs[0] == kdata_base - 0x8a5410) //decryptSelfBlock
    {
        inside = 1;
        kmemcpy(&limit, (void*)regs[3], 8);
    }
    if(!inside)
        trace_start -= trace_frame_size;
}
#endif

static char empty_page[4096];
static int kek1;
static int kek2;
static int kek3;
static int kek4;
static uint64_t kekv1;
static uint64_t kekv2;
static uint64_t kekv3;
static uint64_t kekv4;
static uint64_t kekv5;
static uint64_t kekv6;
static uint64_t kekv7;
static uint64_t kekv8;

static void very_kek(uint64_t* regs)
{
    SKIP_SCHEDULER
#if 0
    if(regs[0] == kdata_base - 0x8a5780) //loadSelfSegment
    {
        uint64_t sp = regs[3];
        kmemcpy((void*)(sp - 0x128), empty_page, 0x128);
        kek1 += 1;
    }
#endif
    if(regs[0] == offsets.loadSelfSegment_watchpoint)
    {
        uint64_t sp = regs[3];
        uint64_t sp_page = sp & -4096;
        uint64_t lr;
        kmemcpy(&lr, (void*)(sp + 0x18), 8);
        if(lr == offsets.loadSelfSegment_watchpoint_lr)
        {
            uint64_t backup[20];
            kmemcpy(backup, (void*)sp, 32 /*24*/);
            backup[4] = kekv1;
            backup[5] = kekv2;
            //backup[3] = backup[4] = kdata_base - 0x28a3a0;
            sp -= 16;
            kmemcpy((void*)sp, backup, 48 /*40*/);
            regs[3] = sp;
            kek2 += 1;
        }
    }
#if 0
    if(regs[0] == kdata_base - 0x8a5546)
    {
        uint64_t restore[2];
        kmemcpy(restore, (void*)regs[3], 16);
        kekv1 = restore[0];
        kekv2 = restore[1];
        regs[3] += 16;
    }
    if(regs[0] == offsets.decryptSelfBlock_watchpoint)
    {
        uint64_t backup[10];
        kmemcpy(backup, (void*)regs[3], 32);
        if(backup[3] == offsets.decryptSelfBlock_watchpoint_lr)
        {
            //backup[5] = backup[3];
            //backup[3] = backup[4] = kdata_base - 0x28a3a0;
            backup[4] = kekv3;
            backup[5] = kekv4;
            backup[6] = kekv5;
            backup[7] = kekv6;
            backup[8] = kekv7;
            backup[9] = kekv8;
            regs[3] -= 48;
            kmemcpy((void*)regs[3], backup, 80);
            kek3 += 1;
        }
    }
#endif
    if(regs[0] == offsets.decryptSelfBlock_epilogue)
    {
        uint64_t restore[6];
        kmemcpy(restore, (void*)regs[3], 48);
        kekv3 = restore[0];
        kekv4 = restore[1];
        kekv5 = restore[2];
        kekv6 = restore[3];
        kekv7 = restore[4];
        kekv8 = restore[5];
        regs[3] += 48;
        kek4 += 1;
    }
}

static void* malloc_locked(size_t sz)
{
    void* ans = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if(mlock(ans, sz))
        asm volatile("hlt");
    return ans;
}

static uint64_t* dump_program = 0;

static void do_dump_at_rip(uint64_t* regs)
{
    SKIP_SCHEDULER
    uint64_t* prg = dump_program;
    while(*prg)
    {
        int use = (regs[0] == *prg++);
        if(use)
        {
            if(*prg == (uint64_t)-1)
                use = 0;
            else if(*prg != 0)
            {
                --*prg;
                if(*prg == 0)
                    *prg = -1;
                else
                    use = 0;
            }
        }
        prg++;
        if(use)
        {
            uint64_t reg;
            if((*prg) == (uint64_t)-1)
                reg = (uint64_t)regs;
            else
                reg = regs[*prg++];
            while(*prg != (uint64_t)-1)
            {
                if(*prg == (uint64_t)-2)
                {
                    prg++;
                    if(*prg == (uint64_t)-2)
                        break;
                    reg += *prg++;
                }
                else
                {
                    uint64_t val;
                    kmemcpy(&val, (void*)(reg + (*prg++)), 8);
                    reg = val;
                }
            }
            prg++;
            *(uint64_t*)(*prg++) = reg;
            reg &= -4096;
            kmemcpy((void*)(*prg++), (void*)reg, 4096);
        }
        else
        {
            while(*prg++ != (uint64_t)-1);
            prg += 2;
        }
    }
}

static uint64_t s_auth_info_for_dynlib[17] = {0x4900000000000002, 0x0, 0x800000000000ff00, 0x0, 0x0, 0x7000700080000000, 0x8000000000000000, 0x0, 0xf0000000ffff4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

static char mailbox_request[16384];
static char mailbox_response[16384];
static char mailbox_fakeresp[128];
static uint64_t mailbox_lr[128];
static uint64_t mailbox_rdx;
static size_t mailbox_n = 0;
static size_t blocks_decrypted = 0;
static char header_backup[0x6a0];
static uint32_t size_backup;
static uint64_t header_ptr;
static int do_fself = 0;
static uint64_t fself_hook_lr;
static char encrypted_memory[4096];
static char decrypted_memory[4096];
static char now_decrypted_memory[4096];
static char faked_decrypts[16384];
static size_t n_faked_decrypts;
static uint64_t self_context;

static void* trace_prog_after_mailbox = 0;

static int ekh = 0x41414140;
static int skh = 0x42424241;

static void trace_mailbox_for_fpkg(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == offsets.sceSblServiceMailbox)
    {
        uint64_t lr;
        kmemcpy(&lr, (void*)regs[3], 8);
        kmemcpy(mailbox_request+128*mailbox_n, (void*)regs[7], 128);
        mailbox_lr[mailbox_n] = lr;
        if(mailbox_n < n_faked_decrypts && mailbox_fakeresp[mailbox_n])
        {
            ekh++;
            skh++;
            uint32_t stuff[4] = {0, 0, ekh, skh};
            kmemcpy((void*)regs[11], stuff, 16);
            mailbox_rdx = regs[11];
            regs[0] = lr;
            regs[5] = mailbox_response[mailbox_n];
            regs[3] += 8;
        }
        mailbox_n++;
        if(mailbox_n == n_faked_decrypts && trace_prog_after_mailbox)
            trace_prog = trace_prog_after_mailbox;
    }
    else if(regs[0] == offsets.sceSblPfsSetKeys) //sceSblPfsSetKeys
    {
        ekh++;
        skh++;
        kmemcpy((void*)regs[12], &ekh, 4);
        kmemcpy((void*)regs[11], &skh, 4);
        kmemcpy(regs, (void*)regs[3], 8);
        regs[5] = 0;
        regs[3] += 8;
        if(trace_prog_after_mailbox)
            trace_prog = trace_prog_after_mailbox;
    }
}

static char* panic_message;

//panic is commonly inlined in sonybsd, there is no reason to trace it
#if 0
static void trace_panic(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == offsets.panic)
    {
        panic_message = (char*)regs[12];
        regs[0] = iret;
        regs[2] &= -257ull;
        regs[3] -= 40;
        kmemcpy((void*)regs[3], regs, 40);
    }
}
#endif

static void trace_cryptasync(uint64_t* regs)
{
    SKIP_SCHEDULER
    if(regs[0] == offsets.sceSblServiceCryptAsync)
    {
        uint64_t req = regs[12];
        uint64_t msg;
        kmemcpy(&msg, (void*)req, 8);
        if(mailbox_n < 128)
        {
            kmemcpy(mailbox_request+128*mailbox_n, (void*)msg, 128);
            if(mailbox_fakeresp[mailbox_n])
            {
                regs[3] -= 16;
                kmemcpy((void*)regs[3], (const uint64_t[1]){0x1234}, 8);
                kmemcpy(regs, (void*)(req+16), 8);
                kmemcpy(regs+12, (void*)(req+24), 8);
                regs[11] = (uint32_t)-2;
            }
        }
        mailbox_n++;
    }
    else if(regs[0] == 0x1234)
    {
        kmemcpy(regs, (void*)(regs[3]+8), 8);
        regs[3] += 16;
        regs[5] = 0;
    }
}

static uint64_t other_thread;

static void* other_thread_fn(void* arg)
{
    other_thread = get_thread();
    //((int(*)())dlsym((void*)0x1, "sceKernelSleep"))(10000000);
    for(;;)
        asm volatile("");
}

static int set_user_gsbase(uint64_t base) 
{
    // unlike sysarch(AMD64_SET_GSBASE), setcontext does not check if the base is below VM_MAXUSER_ADDRESS
    uint64_t data[0x4c0 / 8];
    volatile int resumed = 0;

    if (getcontext((void*)data))
        return -1;

    if (resumed)
        return 0;

    resumed = 1;
    data[0xd0 / 8] |= 2;     // mc_flags |= _MC_HASBASES
    data[0x488 / 8] = base;  // mc_gsbase

    if (setcontext((void*)data))
        return -1;

    __builtin_unreachable();
}

static uint64_t syscall_cfi_table_base = 0;
static void trace_find_syscall_cfi_table_jmp_int3_addr(uint64_t* regs)
{
    // trace_frame_size
    static uint64_t prev_prev_frame[168/8];
    static uint64_t prev_frame[168/8];

    //                 lea     rcx, syscall_cfi_table_base
    //                 mov     rax, [rbp+var_80]
    //
    // syscall_before:
    //                 mov     rbx, [rax+8]
    //                 mov     rax, rbx
    //                 sub     rax, rcx
    //                 ror     rax, 3
    //                 cmp     rax, 37Ah
    //                 ja      cfi_check_fail
    //                 lea     rsi, [rbp+args]
    //                 mov     rdi, r14
    //                 call    rbx

    SKIP_SCHEDULER
    if (syscall_cfi_table_base != 0)
        return;
    
    // some fws have a `mov     rax, gs:0` as the first instruction
    // set user gsbase, its not used anyway
    if (set_user_gsbase(kstack - 0x2000)) {
        return 0;
    }
    
    if (regs[0] == offsets.syscall_before)
    {
        // the syscall_cfi_table_base was loaded into rcx on all fws so far
        // if this fails then this changed, todo
        if (prev_prev_frame[6] != prev_frame[6] && // rcx changed
            (prev_frame[6] < kdata_base && prev_frame[6] > kdata_base - 32 * 1024 * 1024)) // rcx in kernel .text
            syscall_cfi_table_base = prev_frame[6];
    }

    memcpy(prev_prev_frame, prev_frame, sizeof(prev_prev_frame));
    memcpy(prev_frame, regs, sizeof(prev_frame));
}

uint64_t r0gdb_find_syscall_cfi_table_jmp_int3_addr(void) 
{
    if (offsets.syscall_before == kdata_base)
        return 0;

    if(r0gdb_instrument(0))
        return 0;
    int(*p_getppid)() = WRAPPER(getppid);
    trace_prog = trace_find_syscall_cfi_table_jmp_int3_addr;
    if(set_trace())
    {
        trace_prog = 0;
        return 0;
    }
    p_getppid();
    trace_prog = 0;

    if (syscall_cfi_table_base == 0)
        return 0;
        
    // make int3 use r0gdb's int1 stuff
    char og_idt3[16];    
    copyout(og_idt3, offsets.idt+16*3, sizeof(og_idt3));

    uint64_t int1_handler;
    copyout(&int1_handler, offsets.idt+16*1, 2);
    copyout((char*)&int1_handler + 2, offsets.idt+16*1+6, 6);
    uint8_t int1_ist_index;
    copyout(&int1_ist_index, offsets.idt+16*1+4, 1);
    
    kmemcpy((char*)(offsets.idt+16*3), (char*)&int1_handler, 2);
    kmemcpy((char*)(offsets.idt+16*3+6), (char*)&int1_handler+2, 6);
    kmemcpy((char*)(offsets.idt+16*3+4), &int1_ist_index, 1);

    struct regs regs;
    struct regs regs_before;

    uint64_t syscall_cfi_table_jmp_int3_addr = 0;

    // single step first 700 entries to try and find the jmp to int3
    for (int i = 0; i < 700; i++)
    {
        uint64_t entry_rip = syscall_cfi_table_base + i * 8;
        
        // execute jmp of cfi table entry
        memset(&regs, 0, sizeof(regs));
        regs.rip = entry_rip;
        regs.rsp = kstack;
        regs.eflags = 0x102;
        run_in_kernel(&regs);

        if ((regs.rip % 16) != 0 || (regs.rip > entry_rip && regs.rip < entry_rip + 15))
        {
            // what we have just executed was not a jmp, syscall_cfi_table_base is wrong, bail
            break;
        }

        // set arg regs to something valid, in case first instruction is a memory read
        regs.rdi = kstack - 0x2000;
        regs.rsi = kstack - 0x2000;
        regs.rdx = kstack - 0x2000;
        regs.rcx = kstack - 0x2000;
        regs.r8  = kstack - 0x2000;
        regs.r9  = kstack - 0x2000;
        regs.rbp = kstack - 0x2000;
        regs.eflags = 0x102;
        memcpy(&regs_before, &regs, sizeof(regs));

        // run first instruction
        run_in_kernel(&regs);

        // assume if no register changed, except for rip increasing by 1, then we hit an int3
        // there are other instructions that fit this criteria, like nop and hlt, but they realistically wont be here
        if (regs.rip == regs_before.rip + 1 &&
            memcmp(&regs, &regs_before, __builtin_offsetof(struct regs, rip)) == 0 &&
            memcmp((char*)(&regs) + __builtin_offsetof(struct regs, rip) + 8, 
                   (char*)(&regs_before) + __builtin_offsetof(struct regs, rip) + 8, 
                   sizeof(regs) - __builtin_offsetof(struct regs, rip) - 8) == 0)
        {
            // found it
            syscall_cfi_table_jmp_int3_addr = entry_rip;
            break;
        }
    }

    // restore int3
    kmemcpy((char*)(offsets.idt+16*3), og_idt3, sizeof(og_idt3));
    
    return syscall_cfi_table_jmp_int3_addr;
}

int set_offsets(void);

static void r0gdb_init_with_offsets(void)
{
    init_pipe();
    if(!victim_pktopts)
    {
        uint64_t fd;
        copyout(&fd, proc+0x48, 8);
        uint64_t ofiles;
        copyout(&ofiles, fd, 8);
        uint64_t victim_file;
        copyout(&victim_file, ofiles+8+victim_fd*48, 8);
        uint64_t victim_sock;
        copyout(&victim_sock, victim_file, 8);
        uint64_t so_pcb;
        copyout(&so_pcb, victim_sock+24, 8);
        copyout(&victim_pktopts, so_pcb+288, 8);
    }
}

int r0gdb_init(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    master_fd = a;
    victim_fd = b;
    victim_pktopts = c;
    kdata_base = d;
    if(!set_offsets())
    {
        r0gdb_init_with_offsets();
        return 0;
    }
    return -1;
}

//kernel_get_fw_version from sb's sdk
uint32_t r0gdb_get_fw_version(void)
{
    int mib[2] = {1, 46};
    unsigned long size = sizeof(mib);
    unsigned int version = 0;
    sysctl(mib, 2, &version, &size, 0, 0);
    return version;
}
