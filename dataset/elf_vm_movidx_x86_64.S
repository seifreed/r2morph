.intel_syntax noprefix
.global _start
.text
# Scaled-index mov load/store fixture. The whole function is region-reducible
# (balanced sub/add rsp, register-source stores), so the scaled-index accesses
# lower to the loadidx/storeidx micro-ops. Exit code 35 depends on:
#   loadidx a[2] (32-bit, rcx*4) == 30, storeidx a[0] (rdx*4) writing 30 back,
#   and loadidx b[1] (64-bit, rsi*8) == 5.  30 + 5 = 35.
_start:
    sub rsp, 64
    # int a[4] at [rsp] (base+disp register-source stores)
    mov eax, 10
    mov dword ptr [rsp], eax
    mov eax, 20
    mov dword ptr [rsp+4], eax
    mov eax, 30
    mov dword ptr [rsp+8], eax
    mov eax, 40
    mov dword ptr [rsp+12], eax
    # loadidx (32-bit): eax = a[2] via [rsp + rcx*4]
    mov rcx, 2
    mov eax, dword ptr [rsp + rcx*4]
    # storeidx (32-bit): a[0] = eax via [rsp + rdx*4]
    xor edx, edx
    mov dword ptr [rsp + rdx*4], eax
    # qword b[2] at [rsp+32]
    mov rax, 7
    mov qword ptr [rsp+32], rax
    mov rax, 5
    mov qword ptr [rsp+40], rax
    # loadidx (64-bit): rbx = b[1] via [rsp + 32 + rsi*8]
    mov rsi, 1
    mov rbx, qword ptr [rsp + 32 + rsi*8]
    # reload a[0] (base+disp) == 30, add b[1] (5) -> 35
    mov eax, dword ptr [rsp]
    add eax, ebx
    add rsp, 64
    mov edi, eax
    mov eax, 60
    syscall
