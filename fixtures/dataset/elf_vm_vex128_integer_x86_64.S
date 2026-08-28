.intel_syntax noprefix
.global _start
.text
.p2align 4, 0x90
_start:
    movdqa xmm0, xmmword ptr [rip + left]
    movdqa xmm1, xmmword ptr [rip + right]
    vpaddd xmm0, xmm0, xmm1
    vpsubd xmm0, xmm0, xmm1
    vpmulld xmm0, xmm0, xmm1
    vpminsd xmm0, xmm0, xmm1
    vpmaxsd xmm0, xmm0, xmm1
    vpxor xmm2, xmm2, xmm2
    vpor xmm2, xmm2, xmm0
    vpand xmm2, xmm2, xmm1
    movd edi, xmm2
    mov eax, 60
    syscall

.section .rodata
.p2align 4
left:
    .long 1, 2, 3, 4
right:
    .long 10, 20, 30, 40
