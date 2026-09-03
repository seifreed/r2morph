.intel_syntax noprefix
.global _start
.text

_start:
    vmovdqa xmm1, xmmword ptr [rip + word128]

    vpshuflw xmm0, xmm1, 0x1b
    movd eax, xmm0
    cmp eax, 0x00030004
    jne failure

    vpshufhw xmm0, xmm1, 0x1b
    movd eax, xmm0
    cmp eax, 0x00020001
    jne failure

    vmovdqa ymm1, ymmword ptr [rip + word256]

    vpshuflw ymm0, ymm1, 0x1b
    movd eax, xmm0
    cmp eax, 0x00030004
    jne failure
    vextracti128 xmm2, ymm0, 1
    movd eax, xmm2
    cmp eax, 0x000b000c
    jne failure

    vpshufhw ymm0, ymm1, 0x1b
    movd eax, xmm0
    cmp eax, 0x00020001
    jne failure
    vextracti128 xmm2, ymm0, 1
    movd eax, xmm2
    cmp eax, 0x000a0009
    jne failure

    mov edi, 42
    mov eax, 60
    syscall

failure:
    mov edi, 1
    mov eax, 60
    syscall

.fill 0x200, 1, 0x90

.section .rodata
.p2align 5
word128:
    .word 1, 2, 3, 4, 5, 6, 7, 8
word256:
    .word 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
