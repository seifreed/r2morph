.intel_syntax noprefix
.global _start
.text
.p2align 4, 0x90
_start:
    movss xmm0, dword ptr [rip + left]
    movss xmm1, dword ptr [rip + right]
    vaddss xmm2, xmm0, xmm1
    vsubss xmm2, xmm2, xmm1
    vmulss xmm2, xmm2, xmm1
    vdivss xmm2, xmm2, xmm1
    vminss xmm2, xmm2, xmm1
    vmaxss xmm2, xmm2, xmm1
    vminss xmm2, xmm2, xmm0
    cvttss2si eax, xmm2
    mov edi, eax
    mov eax, 60
    syscall

.section .rodata
.p2align 2
left:
    .float 2.0
right:
    .float 3.0
