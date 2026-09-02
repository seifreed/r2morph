.intel_syntax noprefix
.global _start
.text

# Exercise legacy packed 16-bit equality and signed-greater-than comparisons.
# The VM must preserve all eight 16-bit lanes in both operations.
_start:
    mov rax, 0x0007000700070007
    mov [rsp - 32], rax
    mov [rsp - 24], rax
    mov rax, 0x0008000800080008
    mov [rsp - 16], rax
    mov [rsp - 8], rax
    movups xmm0, xmmword ptr [rsp - 32]
    movups xmm1, xmmword ptr [rsp - 32]
    movups xmm2, xmmword ptr [rsp - 16]
    movups xmm3, xmmword ptr [rsp - 32]
    pcmpeqw xmm0, xmm1
    pcmpgtw xmm2, xmm3
    pmovmskb eax, xmm0
    cmp eax, 0xffff
    jne failure
    pmovmskb eax, xmm2
    cmp eax, 0xffff
    jne failure
    mov eax, 60
    mov edi, 42
    syscall

failure:
    mov eax, 60
    mov edi, 1
    syscall
