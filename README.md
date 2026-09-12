# kstuff-lite 

`1.11` builds on the existing kstuff-lite crypto, FSELF, NPDRM, and loader
work. It reduces UELF/KELF transition cost, makes FPU/CR0 handling safer and
faster, and adds detailed opt-in diagnostics.

## Highlights

- Cached translations for fixed per-CPU kernel objects used on every UELF
  entry, including mappings that cross a physical segment boundary.
- Narrow checked trap-frame and stack reads instead of copying unused frame
  prefixes.
- A single-transition debug-register restore and skipped hardware snapshots
  when the current thread does not own active debug registers.
- A validated, normally fault-free CR0 save/TS-clear chain with mandatory
  per-kernel gadgets and no legacy CR0-capture fallback.
- Fast CR0 entry through a one-shot KELF continuation and deferred CR0 restore
  at the final KELF exit.
- Runtime selection between `XSAVEC` and `XSAVE`, with one-time CPUID/XCR0
  discovery and strict save-area validation.
- Expanded opt-in performance and failure metrics through `KSTUFF_OBS=1`.
- Reuse of the loader's existing kernel pipe by prosper0gdb.

## UELF trap and kernel-memory paths

### Narrow checked frame reads

Trap handlers now read only the portion of a saved stack frame that they use.
`fpkg`, `kekcall`, and utility trap handling use checked tail-copy helpers;
mailbox and syscall paths use checked scalar reads and writes. Where the return
address is already known, FSELF handling updates `RSP` and `RIP` directly
instead of reading the same value from kernel memory again.

This reduces `virt2phys` calls and copied bytes without weakening error
handling. A failed read or write returns `EFAULT` or leaves the request on its
normal fallback path instead of consuming partially read state.

### Fixed mapping caches

The following stable per-CPU objects have cached virtual-to-physical mappings:

- the extended trap frame;
- the `justreturn` frame;
- the current-thread pointer in `pcpu`;
- `TSS.RSP0`;
- the `wrmsr` argument area;
- the CR0 enter and exit continuation slots.

The cache can represent two physical segments, so an object crossing a page or
mapping boundary does not need to fall back on every access. Initialization is
checked, publication is atomic, and an uncached checked copy remains available
if a mapping cannot be cached.

The UELF page-table setup also spells out the user, writable, present, and
large-page flags explicitly. Direct-map entries are not made global, avoiding
unsafe stale TLB translations when switching between the kernel and UELF CR3.

## Crypto dispatch

During classification, the fake key is retrieved once and passed to the XTS or
HMAC handler. This removes the former `has_fake_key()` lookup followed by a
second `get_fake_key()` lookup. XTS and HMAC cache selection also performs one
scan that records both a matching entry and the first free entry.

Unhandled or non-fake messages retain the original kernel path, and linked
message chains are still traversed correctly. Snapshot read failures are
counted and fail safely.

## Debug-register transitions

Debug-register restore now enters the verified tail of the kernel
`cpu_switch` implementation and restores DR0, DR1, DR2, DR3, DR6, and DR7 in a
single gadget transition. Each kernel layout uses its own validated entry.

Before installing a watchpoint, the code checks `PCB_DBREGS`. If the flag is
clear, the thread does not own live hardware debug-register state, so a stale
hardware snapshot is skipped and the saved state is initialized as disabled.
PCB flags are accessed as a 32-bit field, and rollback restores both the old
registers and the original ownership flag if installation fails.

KELF 8-byte writes also use a scalar `mov [rdi], rax` store helper instead of
configuring `rep movsb` for every single-qword update.

## FPU and CR0 handling

### CR0 entry

UELF crypto uses SIMD instructions and must preserve kernel FPU state while
temporarily clearing `CR0.TS`. The entry path is a kernel-specific KELF
chain: it single-steps `mov_rax_cr0`, captures the resulting `#DB`, clears TS,
commits the new value, and records all three states without deliberately
causing a second XSAVE/FXSAVE fault. Failure to arm or validate this chain is
reported directly; there is no CR0-capture fallback.

The chain poisons and transfers one compact `0x60`-byte result block,
then validates the saved, cleared, and committed values. A mismatch restores
TS when possible and reports failure instead of trusting partial state.

### Fast entry and deferred restore

UELF arms a one-shot KELF continuation and performs one
`yield()`; KELF resets the hook before running the CR0 chain. This bypasses the
generic full-register gadget return path. The fixed continuation address and
its physical mapping are cached after the first use.

After `XRSTOR`, CR0 restoration is postponed until `uelf_fpu_finish()`, just
before the terminal UELF `HLT`. KELF then restores CR0 and continues through
the normal final exit. Nested FPU users share the outer save/restore pair, so
they do not add extra CR0 or XSAVE transitions.

### XSAVE mode selection

CPUID and XCR0 discovery is performed once per UELF instance. Before using an
architectural save instruction, the code verifies:

- CPUID exposes leaf `0xD`;
- the CPU and OS expose XSAVE/OSXSAVE;
- x87 and SSE are enabled in XCR0;
- XCR0 contains only state components reported by CPUID;
- `CPUID.(D,0):EBX` is within the architectural minimum, the reported maximum,
  and the 4096-byte aligned local buffer.

`XSAVEC` is selected when `CPUID.(D,1):EAX[1]` advertises it; otherwise the code
uses `XSAVE`. Restore always uses `XRSTOR`. `XSAVEOPT` is deliberately not used
because the scratch buffer is not guaranteed to contain the same owner's
previous state. An unusable configuration disables FPU entry cleanly instead
of overflowing the buffer or executing an unsupported instruction.

## prosper0gdb loader handoff

The loader passes prosper0gdb a versioned bootstrap structure containing its
existing read/write pipe descriptors and kernel pipe address. prosper0gdb
reuses that primitive instead of allocating and resolving another pipe. The
older `victim_pktopts` ABI remains recognized for callers that do not provide
the bootstrap magic.

## Observability

Build with metrics and the debug reader enabled:

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
KSTUFF_OBS=1 ./ci-ps5-kstuff-ldr.sh
```

A normal build keeps the extra counters out of hot paths:

```sh
./ci-ps5-kstuff-ldr.sh
```

The added metrics cover:

- UELF entries, checked frame failures, and total/max entry cycles;
- gadget calls, failures, result-readback reductions, and cycles;
- scalar and bulk kernel copies;
- crypto snapshot reads, failures, and cycles;
- mapping-cache hits, misses, and fallbacks;
- debug-register reads, writes, single-transition chains, and skipped
  snapshots;
- CR0 fast-entry/deferred-restore arms, failures, hook-cache use,
  and arm cost;
- FPU enter/exit, XSAVE/XSAVEC/XRSTOR counts, failures, and cycle cost;
- PLAINTEXT_NOAUTH FE/FF index acquisition and exact transient-context cleanup
  before `ppfs_put_{cmac,xts}_index` (`PPRCLN01` word-log records).

`ps5-kstuff/debug-reader.c` prints these counters from the shared observation
area. Metrics are intended for comparison runs; they add measurement overhead
and should not be used as release-performance numbers.
