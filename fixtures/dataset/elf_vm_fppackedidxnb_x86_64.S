.intel_syntax noprefix
.global _start
.text
# Region-path packed SIMD with absolute no-base indexed memory. The vector starts
# at table + 8, is doubled with paddd, stored through the same address shape, and
# loaded again before movd extracts the low lane. Net exit code is 6.
_start:
    mov rcx, 1
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
    .long 1, 2, 3, 4
output:
    .long 0, 0, 0, 0
.zero 8
