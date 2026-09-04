.intel_syntax noprefix
.global _start
.text
# Region-path packed SIMD with absolute no-base indexed memory. The vector starts
# at table + 16, is doubled with paddd, stored through the same address shape,
# and loaded again before movd extracts the low lane. The 16-byte offset keeps
# paddd's legacy m128 operand aligned. Net exit code is 6.
_start:
    mov rcx, 2
    movups xmm0, xmmword ptr [table + rcx*8]
    paddd xmm0, xmmword ptr [table + rcx*8]
    movups xmmword ptr [output + rcx*8], xmm0
    movups xmm1, xmmword ptr [output + rcx*8]
    movd edi, xmm1
    mov eax, 60
    syscall
.data
.align 16
table:
    .long 1, 2, 3, 4, 3, 4, 5, 6
output:
    .long 0, 0, 0, 0, 0, 0, 0, 0
