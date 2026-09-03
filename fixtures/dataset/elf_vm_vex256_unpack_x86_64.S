.intel_syntax noprefix
.global _start
.text

_start:
    vmovdqa ymm1, ymmword ptr [rip + dword_left]
    vmovdqa ymm2, ymmword ptr [rip + dword_right]

    vpunpckldq ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 1
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 5
    jne failure

    vpunpcklqdq ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 1
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 5
    jne failure

    vmovdqa ymm1, ymmword ptr [rip + byte_left]
    vmovdqa ymm2, ymmword ptr [rip + byte_right]
    vpunpckhbw ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 0x22122111
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 0x42324131
    jne failure

    vmovdqa ymm1, ymmword ptr [rip + word_left]
    vmovdqa ymm2, ymmword ptr [rip + word_right]
    vpunpckhwd ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 0x00320005
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 0x0096000f
    jne failure

    vmovdqa ymm1, ymmword ptr [rip + dword_left]
    vmovdqa ymm2, ymmword ptr [rip + dword_right]
    vpunpckhdq ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 3
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 7
    jne failure

    vpunpckhqdq ymm0, ymm1, ymm2
    movd eax, xmm0
    cmp eax, 3
    jne failure
    vextracti128 xmm3, ymm0, 1
    movd eax, xmm3
    cmp eax, 7
    jne failure

    mov edi, 42
    mov eax, 60
    syscall

failure:
    mov edi, 1
    mov eax, 60
    syscall

.section .rodata
.p2align 5
byte_left:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    .byte 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
byte_right:
    .byte 10, 20, 30, 40, 50, 60, 70, 80, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
    .byte 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58
word_left:
    .word 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 18, 19, 20, 21, 22
word_right:
    .word 10, 20, 30, 40, 50, 60, 70, 80, 150, 160, 170, 180, 190, 200, 210, 220
dword_left:
    .long 1, 2, 3, 4, 5, 6, 7, 8
dword_right:
    .long 10, 20, 30, 40, 50, 60, 70, 80
