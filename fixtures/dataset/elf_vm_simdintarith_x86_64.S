.intel_syntax noprefix
.global _start
.text
# Packed integer arithmetic: add and subtract all four dword lanes. The stores
# make both intermediate results observable through the process exit code.
_start:
    mov rax, 0x0000000500000014
    mov [rsp - 16], rax
    mov rax, 0x0000000800000007
    mov [rsp - 8], rax
    mov rax, 0x0000002500000016
    mov [rsp - 32], rax
    mov rax, 0x0000000200000001
    mov [rsp - 24], rax
    lea rbx, [rsp - 16]
    lea rdx, [rsp - 32]
    movups xmm0, xmmword ptr [rbx]
    movups xmm1, xmmword ptr [rdx]
    paddd xmm0, xmm1
    movups [rsp - 48], xmm0
    mov edi, dword ptr [rsp - 48]
    psubd xmm0, xmm1
    movups [rsp - 64], xmm0
    add edi, dword ptr [rsp - 64]
    mov eax, 60
    syscall
