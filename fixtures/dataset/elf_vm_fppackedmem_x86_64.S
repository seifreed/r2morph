.intel_syntax noprefix
.global _start
.text
# Packed memory-source arithmetic (vectorized accumulation): load a vector into
# xmm0 and add a second vector straight from memory (addpd xmm0, [base]:
# [20,5] + [22,37] = [42,42]), then truncate the low lane. The VM must load the
# 128-bit memory operand and run the packed op across all lanes. Net exit code 42.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 16], rax
    mov rax, 0x4014000000000000
    mov [rsp - 8], rax
    mov rax, 0x4036000000000000
    mov [rsp - 32], rax
    mov rax, 0x4042800000000000
    mov [rsp - 24], rax
    lea rbx, [rsp - 16]
    lea rdx, [rsp - 32]
    movups xmm0, xmmword ptr [rbx]
    addpd xmm0, xmmword ptr [rdx]
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
