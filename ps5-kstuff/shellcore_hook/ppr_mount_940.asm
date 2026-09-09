BITS 64
ORG 0x17DEB50

; SceShellCore 9.40 retail hook for the sole sceFsMountPprPkg call site.
; The blob is copied to the zero-filled tail of the final executable page.
; Keep this file freestanding: it must not contain relocations or external data.

%define PPR_CONTROL_SYSCALL              0x700000027
%define PPR_CONTROL_MAGIC                0x505052504C41494E
%define PPR_CONTROL_VERSION              8
%define PPR_CONTROL_CLEAR                0
%define PPR_CONTROL_BEGIN                1
%define PPR_CONTROL_WRITE                2
%define PPR_CONTROL_CHECK                3
%define PPR_CONTROL_ARM                  9

%define PPR_FIH_SIZE                     0x1000
%define PPR_SUPERBLOCK_SIZE              0x5A0
%define PPR_STAGING_SIZE                 (PPR_FIH_SIZE + PPR_SUPERBLOCK_SIZE)
%define PPR_STACK_SIZE                   0x15B8

%define PPR_OPT_STAGE1_IMAGE             0x00
%define PPR_OPT_STAGE1_SUPERBLOCK_OFFSET 0x20

%define PPR_SUPERBLOCK_MODE_OFFSET       0x1C
%define PPR_SUPERBLOCK_SEED_OFFSET       0x370
%define PPR_MODE_NATIVE_ENCRYPTED        0x000D

%define LIBKERNEL_CLOSE_PLT              0x17D5DE0
%define LIBKERNEL_OPEN_PLT               0x17D6F00
%define LIBKERNEL_PREAD_PLT              0x17D7050
%define SCE_FS_MOUNT_PPR_PKG_PLT         0x17D92E0
%define PPR_SYSCALL_TARGET_PLACEHOLDER   0x4C43535953525050

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

    test r12, r12
    jz .call_original
    mov rdi, [r12 + PPR_OPT_STAGE1_IMAGE]
    test rdi, rdi
    jz .call_original

    xor esi, esi                    ; O_RDONLY
    xor edx, edx
    call LIBKERNEL_OPEN_PLT
    test eax, eax
    js .call_original
    mov ebx, eax                    ; fd

    mov edi, ebx
    mov rsi, rsp
    mov edx, PPR_FIH_SIZE
    xor ecx, ecx
    call .pread_exact
    test eax, eax
    jnz .close_and_call_original

    mov edi, ebx
    lea rsi, [rsp + PPR_FIH_SIZE]
    mov edx, PPR_SUPERBLOCK_SIZE
    mov rcx, [r12 + PPR_OPT_STAGE1_SUPERBLOCK_OFFSET]
    call .pread_exact
    test eax, eax
    jnz .close_and_call_original

    mov edi, ebx
    call LIBKERNEL_CLOSE_PLT

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

    ; BEGIN(version=8)
    mov esi, PPR_CONTROL_BEGIN
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call .ppr_control
    jc .retry_begin
    test rax, rax
    jz .begin_ready

.retry_begin:
    ; Recover a partial same-thread BEGIN/ARM left by an interrupted call.
    ; CLEAR cannot steal staging owned by a different thread.
    xor r8d, r8d
    call .ppr_clear
    mov esi, PPR_CONTROL_BEGIN
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call .ppr_control
    jc .call_original
    test rax, rax
    jnz .call_original

.begin_ready:
    mov r15d, 1

    ; WRITE(offset, 0, word0, word1), 16 bytes per request.
    xor ebx, ebx
.write_loop:
    mov esi, PPR_CONTROL_WRITE
    mov edx, ebx
    xor r10d, r10d
    mov r8, [rsp + rbx]
    mov r9, [rsp + rbx + 8]
    call .ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol
    add ebx, 16
    cmp ebx, PPR_STAGING_SIZE
    jb .write_loop

    ; CHECK must return a zero validation mask.
    mov esi, PPR_CONTROL_CHECK
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call .ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol

    ; ARM the one-shot same-thread plaintext session.
    mov esi, PPR_CONTROL_ARM
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call .ppr_control
    jc .abort_protocol
    test rax, rax
    jnz .abort_protocol
    mov r15d, 2
    jmp .call_original

.close_and_call_original:
    mov edi, ebx
    call LIBKERNEL_CLOSE_PLT
    jmp .call_original

.abort_protocol:
    xor r8d, r8d                   ; protocol abort, no mount result
    call .ppr_clear
    xor r15d, r15d

.call_original:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call SCE_FS_MOUNT_PPR_PKG_PLT
    mov ebx, eax

    cmp r15d, 2
    jne .return_result
    mov r8d, ebx                   ; complete lifecycle on mount failure
    call .ppr_clear

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
    call LIBKERNEL_PREAD_PLT
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
.ppr_control:
    xor ecx, ecx                    ; getpid+7 moves RCX to syscall R10
    mov rdi, PPR_CONTROL_MAGIC
    mov rax, PPR_CONTROL_SYSCALL
    ; ShellCore's executable segment is execute-only.  Keep the patched
    ; trampoline address in the instruction stream so it is fetched as code,
    ; rather than loading a qword from the cave as data.
    mov r11, PPR_SYSCALL_TARGET_PLACEHOLDER
    call r11
    ret

.ppr_clear:
    push rbx
    mov rbx, r8
    mov esi, PPR_CONTROL_CLEAR
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r9d, r9d
    call .ppr_control
    test rax, rax
    jz .ppr_clear_done
    mov r8, rbx
    mov esi, PPR_CONTROL_CLEAR
    mov edx, PPR_CONTROL_VERSION
    xor r10d, r10d
    xor r9d, r9d
    call .ppr_control
.ppr_clear_done:
    pop rbx
    ret
