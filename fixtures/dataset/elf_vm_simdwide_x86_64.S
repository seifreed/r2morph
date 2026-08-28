.intel_syntax noprefix
.global _start
.text

_start:
    lea rbx, [rip + vectors]
    movups xmm0, xmmword ptr [rbx]
    movups xmm1, xmmword ptr [rbx + 16]
    paddb xmm0, xmm1
    psubb xmm0, xmm1
    paddw xmm0, xmm1
    psubw xmm0, xmm1
    paddd xmm0, xmm1
    psubd xmm0, xmm1
    paddq xmm0, xmm1
    psubq xmm0, xmm1
    pmulld xmm0, xmm1
    pminsd xmm0, xmm1
    pmaxsd xmm0, xmm1
    pcmpeqd xmm0, xmm1
    pcmpgtd xmm0, xmm1
    pslld xmm0, xmm1
    psrld xmm0, xmm1
    psrad xmm0, xmm1
    movd edi, xmm0
    and edi, 0x7f
    mov eax, 60
    syscall

.section .rodata
.balign 16
vectors:
    .long 1, 2, 3, 4
    .long 4, 3, 2, 1
