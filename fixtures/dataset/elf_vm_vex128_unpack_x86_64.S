.intel_syntax noprefix
.global _start
.text

_start:
    movdqa xmm1, xmmword ptr [rip + dword_left]
    movdqa xmm2, xmmword ptr [rip + dword_right]

    vpunpckldq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 1
    jne failure

    vpunpcklqdq xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 1
    jne failure

    movdqa xmm1, xmmword ptr [rip + byte_left]
    movdqa xmm2, xmmword ptr [rip + byte_right]
    vpunpckhbw xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 0x22122111
    jne failure

    movdqa xmm1, xmmword ptr [rip + word_left]
    movdqa xmm2, xmmword ptr [rip + word_right]
    vpunpckhwd xmm0, xmm1, xmm2
    movd eax, xmm0
    cmp eax, 0x00320005
    jne failure

    movdqa xmm1, xmmword ptr [rip + dword_left]
    movdqa xmm2, xmmword ptr [rip + dword_right]
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
byte_left:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
byte_right:
    .byte 10, 20, 30, 40, 50, 60, 70, 80, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
word_left:
    .word 1, 2, 3, 4, 5, 6, 7, 8
word_right:
    .word 10, 20, 30, 40, 50, 60, 70, 80
dword_left:
    .long 1, 2, 3, 4
dword_right:
    .long 10, 20, 30, 40
