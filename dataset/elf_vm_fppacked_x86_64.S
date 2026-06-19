.intel_syntax noprefix
.global _start
.text
# Packed-SIMD virtualization: build two 128-bit vectors of doubles on the stack,
# load them with movups (packed 128-bit load), add them lane-wise with addpd
# ([20.0,5.0] + [22.0,37.0] = [42.0,42.0]), and truncate the low lane to an int.
# The VM must move whole 128-bit values and run the packed op across all lanes.
# Net exit code 42.
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
    movups xmm1, xmmword ptr [rdx]
    addpd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
