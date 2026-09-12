BITS 64

%ifndef KSTUFF_OBS
%define KSTUFF_OBS 0
%endif

; Relocatable SceShellCore retail wrappers for the four game-package APIs.
; The blob is installed in a private RX mapping and the corresponding PLT GOT
; slots are redirected to its entry points.  Keep this file freestanding: it
; must not contain relocations or external data.

%define PPR_CONTROL_SYSCALL              0x700000027
%define PPR_CONTROL_MAGIC                0x505052504C41494E
%define PPR_CONTROL_VERSION              8
%define PPR_CONTROL_CLEAR                0
%define PPR_CONTROL_BEGIN                1
%define PPR_CONTROL_WRITE                2
%define PPR_CONTROL_CHECK                3
%define PPR_CONTROL_ARM                  9
%define PPR_CONTROL_TRACE                10
%define PPR_CONTROL_SCOPE_ENTER          11
%define PPR_CONTROL_SCOPE_LEAVE          12

%define FPKG_SCOPE_GAME_MOUNT            1
%define FPKG_SCOPE_GAME_UNMOUNT          2
%define FPKG_SCOPE_PPR_MOUNT             3
%define FPKG_SCOPE_PPR_UNMOUNT           4
%define PPR_HOOK_SCOPE_BIT               0x100

%define PPR_FIH_SIZE                     0x1000
%define PPR_SUPERBLOCK_SIZE              0x5A0
%define PPR_STAGING_SIZE                 (PPR_FIH_SIZE + PPR_SUPERBLOCK_SIZE)
%define PPR_STACK_SIZE                   0x15B8

%define PPR_OPT_STAGE1_IMAGE             0x00
%define PPR_OPT_STAGE1_SUPERBLOCK_OFFSET 0x20

%define PPR_SUPERBLOCK_MODE_OFFSET       0x1C
%define PPR_SUPERBLOCK_SEED_OFFSET       0x370
%define PPR_MODE_NATIVE_ENCRYPTED        0x000D

%define PPR_SYSCALL_TARGET_PLACEHOLDER   0x4C43535953525050
%define PPR_CLOSE_TARGET_PLACEHOLDER     0x3145534F4C435250
%define PPR_OPEN_TARGET_PLACEHOLDER      0x314E45504F525050
%define PPR_PREAD_TARGET_PLACEHOLDER     0x3144414552525050
%define PPR_MOUNT_TARGET_PLACEHOLDER     0x31544E554D525050
%define GAME_MOUNT_TARGET_PLACEHOLDER    0x31544E554D454D47
%define GAME_UNMOUNT_TARGET_PLACEHOLDER  0x31544D55454D4147
%define PPR_UNMOUNT_TARGET_PLACEHOLDER   0x31544D5552505050

%define GAME_MOUNT_ENTRY_MARKER          0x314D47454B504746
%define GAME_UNMOUNT_ENTRY_MARKER        0x315547454B504746
%define PPR_UNMOUNT_ENTRY_MARKER         0x315550504B504746

%macro CALL_ABS_PLACEHOLDER 1
    mov r11, %1
    call r11
%endmacro

ppr_mount_940_hook:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, PPR_STACK_SIZE

    mov r12, rdi                    ; SceFsMountPprPkgOpt *
    mov r13, rsi                    ; stage-1 unit output
    mov r14, rdx                    ; stage-2 unit output
    xor r15d, r15d                  ; 0=none, 1=BEGIN, 2=ARMED

    ; The scope is active for the complete public API call, including native
    ; mounts.  If ENTER fails, the stock call still runs but kstuff will not
    ; arm any nmount traps (fail closed for fake/plaintext handling).
    mov esi, PPR_CONTROL_SCOPE_ENTER
    mov edx, PPR_CONTROL_VERSION
    mov r8d, FPKG_SCOPE_PPR_MOUNT
    xor r9d, r9d
    call ppr_control
    test rax, rax
    jnz .scope_entered
    or r15d, PPR_HOOK_SCOPE_BIT
.scope_entered:

    test r12, r12
    jz .call_original
    mov rdi, [r12 + PPR_OPT_STAGE1_IMAGE]
    test rdi, rdi
    jz .call_original

    mov edx, 1                     ; entered the patched call site
    call ppr_trace
    mov rdi, [r12 + PPR_OPT_STAGE1_IMAGE]

    xor esi, esi                    ; O_RDONLY
    xor edx, edx
    CALL_ABS_PLACEHOLDER PPR_OPEN_TARGET_PLACEHOLDER
    test eax, eax
    js .call_original
    mov ebx, eax                    ; fd

    mov edx, 2                     ; package file opened
    call ppr_trace

    mov edi, ebx
    mov rsi, rsp
    mov edx, PPR_FIH_SIZE
    xor ecx, ecx
    call .pread_exact
    test eax, eax
    jnz .close_and_call_original

    mov edx, 3                     ; FIH snapshot read
    call ppr_trace

    mov edi, ebx
    lea rsi, [rsp + PPR_FIH_SIZE]
    mov edx, PPR_SUPERBLOCK_SIZE
    ; ShellCore stores the package-absolute outer superblock offset here.
    ; libSceFsInternalForVsh later subtracts opt+0x18 only when it creates
    ; the kernel-relative mount option; pread itself uses opt+0x20 verbatim.
    mov rcx, [r12 + PPR_OPT_STAGE1_SUPERBLOCK_OFFSET]
    call .pread_exact
    test eax, eax
    jnz .close_and_call_original

    ; TRACE stage 4 carries the first half of the marker actually read from
    ; disk.  This distinguishes an old-layout superblock offset from a failed
    ; control syscall without dereferencing ShellCore memory in the kernel.
    mov r8, [rsp + PPR_FIH_SIZE + PPR_SUPERBLOCK_SEED_OFFSET]
    mov edx, 4                     ; outer superblock snapshot read
    call ppr_trace

    mov edi, ebx
    CALL_ABS_PLACEHOLDER PPR_CLOSE_TARGET_PLACEHOLDER

    ; Avoid invoking the comparatively expensive control protocol for native
    ; packages. Full structural validation is performed again by kstuff CHECK.
    cmp dword [rsp], 0x4849467F     ; "\x7fFIH"
    jne .call_original
    cmp word [rsp + PPR_FIH_SIZE + PPR_SUPERBLOCK_MODE_OFFSET], PPR_MODE_NATIVE_ENCRYPTED
    jne .call_original
    mov rax, 0x4E49414C50525050     ; "PPRPLAIN" in memory byte order
    cmp [rsp + PPR_FIH_SIZE + PPR_SUPERBLOCK_SEED_OFFSET], rax
    jne .call_original
    mov rax, 0x21485455414F4E2D     ; "-NOAUTH!" in memory byte order
    cmp [rsp + PPR_FIH_SIZE + PPR_SUPERBLOCK_SEED_OFFSET + 8], rax
    jne .call_original

    mov edx, 5                     ; plaintext/no-auth marker accepted
    call ppr_trace

    ; BEGIN(version=8)
    mov esi, PPR_CONTROL_BEGIN
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call ppr_control
    jc .retry_begin
    test rax, rax
    jz .begin_ready

.retry_begin:
    ; Recover a partial same-thread BEGIN/ARM left by an interrupted call.
    ; CLEAR cannot steal staging owned by a different thread.
    xor r8d, r8d
    call ppr_clear
    mov esi, PPR_CONTROL_BEGIN
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call ppr_control
    jc .call_original
    test rax, rax
    jnz .call_original

.begin_ready:
    or r15d, 1
    mov edx, 6                     ; staging ownership acquired
    call ppr_trace

    ; WRITE(offset, 0, word0, word1), 16 bytes per request.
    xor ebx, ebx
.write_loop:
    mov esi, PPR_CONTROL_WRITE
    mov edx, ebx
    xor r10d, r10d
    mov r8, [rsp + rbx]
    mov r9, [rsp + rbx + 8]
    call ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol
    add ebx, 16
    cmp ebx, PPR_STAGING_SIZE
    jb .write_loop

    mov edx, 7                     ; complete snapshot transferred
    call ppr_trace

    ; CHECK must return a zero validation mask.
    mov esi, PPR_CONTROL_CHECK
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol

    mov edx, 8                     ; kernel-side validation passed
    call ppr_trace

    ; ARM the one-shot same-thread plaintext session.
    mov esi, PPR_CONTROL_ARM
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol
    and r15d, PPR_HOOK_SCOPE_BIT
    or r15d, 2
    mov edx, 9                     ; one-shot mount latch armed
    call ppr_trace
    jmp .call_original

.close_and_call_original:
    mov edi, ebx
    CALL_ABS_PLACEHOLDER PPR_CLOSE_TARGET_PLACEHOLDER
    jmp .call_original

.abort_protocol:
    xor r8d, r8d                   ; protocol abort, no mount result
    call ppr_clear
    and r15d, PPR_HOOK_SCOPE_BIT

.call_original:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    CALL_ABS_PLACEHOLDER PPR_MOUNT_TARGET_PLACEHOLDER
    mov ebx, eax

    mov eax, r15d
    and eax, 3
    cmp eax, 2
    jne .leave_scope
    mov r8d, ebx                   ; complete lifecycle on mount failure
    call ppr_clear

.leave_scope:
    test r15d, PPR_HOOK_SCOPE_BIT
    jz .return_result
    mov esi, PPR_CONTROL_SCOPE_LEAVE
    mov edx, PPR_CONTROL_VERSION
    mov r8d, FPKG_SCOPE_PPR_MOUNT
    mov r9d, ebx
    call ppr_control

.return_result:
    mov eax, ebx
    add rsp, PPR_STACK_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; rdi=fd, rsi=buffer, rdx=size, rcx=file offset
; Returns zero only after the complete range has been read.
.pread_exact:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
.pread_loop:
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    mov rcx, r14
    CALL_ABS_PLACEHOLDER PPR_PREAD_TARGET_PLACEHOLDER
    test rax, rax
    jle .pread_failed
    add r12, rax
    add r14, rax
    sub r13, rax
    jne .pread_loop
    xor eax, eax
    jmp .pread_return
.pread_failed:
    mov eax, -1
.pread_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Inputs follow the registers captured by kekcall:
; RSI=operation, RDX=arg0, R8=arg2, R9=arg3. R10/arg1 is not captured.
ppr_control:
    xor ecx, ecx                    ; getpid+7 moves RCX to syscall R10
    mov rdi, PPR_CONTROL_MAGIC
    mov rax, PPR_CONTROL_SYSCALL
    ; Keep the patched trampoline address in the instruction stream so the
    ; wrapper stays freestanding and does not need a writable data mapping.
    mov r11, PPR_SYSCALL_TARGET_PLACEHOLDER
    call r11
    ret

; EDX is the last successfully completed hook stage.  The trace is advisory:
; failure to record it must never change the stock mount path.
ppr_trace:
%if KSTUFF_OBS
    push rbx
    mov ebx, edx
    mov esi, PPR_CONTROL_TRACE
    xor r10d, r10d
    xor r9d, r9d
    call ppr_control
    mov edx, ebx
    pop rbx
%endif
    ret

ppr_clear:
    push rbx
    mov rbx, r8
    mov esi, PPR_CONTROL_CLEAR
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r9d, r9d
    call ppr_control
    test rax, rax
    jz .ppr_clear_done
    mov r8, rbx
    mov esi, PPR_CONTROL_CLEAR
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r9d, r9d
    call ppr_control
.ppr_clear_done:
    pop rbx
    ret

; The three simple wrappers share one body.  Their public APIs may evolve,
; so preserve all six integer argument registers rather than relying on a
; firmware-specific prototype.  R10 carries the scope id and R11 the original
; resolved import target.
fpkg_scope_wrapper:
    push r11
    push r10
    push r9
    push r8
    push rcx
    push rdx
    push rsi
    push rdi
    sub rsp, 24

    mov byte [rsp + 8], 0
    mov esi, PPR_CONTROL_SCOPE_ENTER
    mov edx, PPR_CONTROL_VERSION
    mov r8, [rsp + 72]
    xor r9d, r9d
    call ppr_control
    test rax, rax
    setz byte [rsp + 8]

    mov rdi, [rsp + 24]
    mov rsi, [rsp + 32]
    mov rdx, [rsp + 40]
    mov rcx, [rsp + 48]
    mov r8,  [rsp + 56]
    mov r9,  [rsp + 64]
    call qword [rsp + 80]
    mov [rsp], eax

    cmp byte [rsp + 8], 0
    je .return
    mov esi, PPR_CONTROL_SCOPE_LEAVE
    mov edx, PPR_CONTROL_VERSION
    mov r8, [rsp + 72]
    mov r9d, [rsp]
    call ppr_control

.return:
    mov eax, [rsp]
    add rsp, 24
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop r8
    pop r9
    pop r10
    pop r11
    ret

    dq GAME_MOUNT_ENTRY_MARKER
game_mount_hook:
    mov r10d, FPKG_SCOPE_GAME_MOUNT
    mov r11, GAME_MOUNT_TARGET_PLACEHOLDER
    jmp fpkg_scope_wrapper

    dq GAME_UNMOUNT_ENTRY_MARKER
game_unmount_hook:
    mov r10d, FPKG_SCOPE_GAME_UNMOUNT
    mov r11, GAME_UNMOUNT_TARGET_PLACEHOLDER
    jmp fpkg_scope_wrapper

    dq PPR_UNMOUNT_ENTRY_MARKER
ppr_unmount_hook:
    mov r10d, FPKG_SCOPE_PPR_UNMOUNT
    mov r11, PPR_UNMOUNT_TARGET_PLACEHOLDER
    jmp fpkg_scope_wrapper
