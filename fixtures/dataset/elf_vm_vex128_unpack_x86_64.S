.intel_syntax noprefix
.global _start
.text

_start:
    movdqa xmm1, xmmword ptr [rip + left]
    movdqa xmm2, xmmword ptr [rip + right]

    vpunpckldq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 1
    jne failure

    vpunpcklqdq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 1
    jne failure

    vpunpckhbw xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 0x22121111
    jne failure

    vpunpckhwd xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 0x000f0005
    jne failure

    vpunpckhdq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 3
    jne failure

    vpunpckhqdq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 3
    jne failure

    mov edi, 42
    mov eax, 60
    syscall

failure:
    mov edi, 1
    mov eax, 60
    syscall

.section .rodata
.p2align 4
left:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
right:
    .byte 10, 20, 30, 40, 50, 60, 70, 80, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
