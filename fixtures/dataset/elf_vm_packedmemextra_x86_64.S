.intel_syntax noprefix
.global _start
.text
# Legacy packed SIMD with a memory source. Reverse the input bytes with pshufb
# and return the first output byte through the Linux exit syscall.
_start:
    lea rsi, [input]
    lea rdi, [mask]
    lea rdx, [output]
    movdqu xmm0, [rsi]
    pshufb xmm0, [rdi]
    movdqu [rdx], xmm0
    movzx edi, byte ptr [rdx]
    mov eax, 60
    syscall
.data
.align 16
input:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
mask:
    .byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
output:
    .zero 16
