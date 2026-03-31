# kstuff-lite-dr: What's New

- `fpkg` handling and related crypto paths were improved.
  A lot of internal logic was sped up: fewer repeated calculations, fewer repeated memory reads, and faster handling of adjacent data blocks.

- `FSELF` handling was improved.
  Parsing and patching now happen more carefully and more efficiently, with extra protection against repeated-access edge cases.

- Startup and early initialization were sped up.
  Process lookup and internal memory setup were optimized. Some unnecessary allocations and repeated copies were removed.

- Protection against freezes and kernel panics was improved.
  Critical paths now perform safer validation. If important data cannot be read or written correctly, the code more often tries to stop safely instead of continuing with corrupted state.

- Automatic mounting can now be disabled.
  This is useful if you want a more controlled startup flow or if you are debugging.

## Main changes by subsystem

### 1. Payload loading and startup

- Memory for loading the module is now allocated automatically in the required size.
- The loader startup path was optimized.
- `CR3` preparation and related setup were improved.
- A more compatible `ShellCore` process lookup path was restored, to avoid trading too much stability for aggressive optimization.
- A prepared zero buffer is now reused instead of clearing memory the slow way each time.

What this improves:
- faster startup;
- fewer unnecessary operations during loading;
- lower chance of hitting unstable behavior during early initialization.

### 2. `fpkg` and PFS crypto handling

- Caches were added for crypto state.
- Expanded `XTS` keys and `HMAC-SHA256` state are now cached.
- Virtual-to-physical translation was sped up in crypto paths.
- Adjacent `XTS` messages can now be processed together.
- A direct `DMEM` fast path was added for `XTS` sectors.
- Batched `XTS` handling for `fpkg` was optimized.
- A shared slow temporary buffer was removed.
- `HMAC-SHA256` was specialized for the fake-key crypto paths that are actually used.

What this improves:
- faster `fpkg` mounting and processing;
- less redundant crypto work;
- lower overhead in repeated operations.

### 3. `FSELF` handling

- A cache was added for already parsed `FSELF` headers.
- A cache was added for the active `SELF` context within a single system call.
- Extra validation was added so an old and a new object are not confused if the same address gets reused.
- `authinfo` loading became lazy: it is only read when it is actually needed.
- `SELF` block copying became safer:
  overlapping memory ranges are now handled correctly;
  no-op copies are skipped;
  unnecessary reads were reduced.

What this improves:
- faster repeated `SELF` processing;
- fewer unnecessary kernel memory reads;
- lower risk of corrupting data in complex loading scenarios.

### 4. NPDRM and license-related handling

- A cache was added for the debug `RIF` key schedule.
- Internal hashing was moved to a lighter and faster wrapper.
- Extra nested FPU transitions were removed where the FPU was already held.
- The `NPDRM` handler now deals with errors more carefully and with slightly lower fixed overhead.

What this improves:
- less unnecessary work in license and key-related paths;
- more predictable behavior when something goes wrong.

### 5. Crypto library and Zen 2 optimization

- `libtomcrypt` was replaced with a faster minimal path based on `isa-l_crypto`.
- A custom minimal PS5 adapter for `isa-l_crypto` was added.
- A dedicated fast `SHA-256` path optimized for `Zen 2` was added.
- `uelf` and the crypto-related parts of the build are now better tuned for the PS5 CPU.
- Optimization settings were made safer and more predictable.

What this improves:
- higher speed in real crypto workloads;
- less unnecessary code;
- better fit for actual PS5 hardware.

### 6. Reliability and error handling

- `fsbase` offset lookup in `kekcall` was fixed.
- A case where a fake key could remain half-broken after a partial failure was fixed.
- Checked helpers were added for reading and writing sensitive kernel data.
- Error handling was improved in `syscall`, `trap`, `mailbox`, `FSELF`, `fpkg`, and `NPDRM` paths.
- Debug register save and restore handling was fixed.
- FPU entry failures are now handled explicitly instead of being ignored.

What this improves:
- lower chance of kernel panics caused by corrupted state;
- better behavior in rare failures and edge cases;
- safer debugging.
