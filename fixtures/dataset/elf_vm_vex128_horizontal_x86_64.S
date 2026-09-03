.intel_syntax noprefix
.global _start
.text

_start:
    movdqa xmm1, xmmword ptr [rip + words_left]
    vphaddw xmm0, xmm1, xmmword ptr [rip + words_right]
    movd eax, xmm0
    cmp eax, 0x00070003
    jne failure

    vphsubw xmm0, xmm1, xmmword ptr [rip + words_right]
    movd eax, xmm0
    cmp eax, 0xffffffff
    jne failure

    movdqa xmm1, xmmword ptr [rip + signed_left]
    vphaddsw xmm0, xmm1, xmmword ptr [rip + signed_right]
    movd eax, xmm0
    cmp eax, 0x7fff7fff
    jne failure

    vphsubsw xmm0, xmm1, xmmword ptr [rip + signed_right]
    movd eax, xmm0
    cmp eax, 0x00028000
    jne failure

    movdqa xmm1, xmmword ptr [rip + dwords_left]
    vphaddd xmm0, xmm1, xmmword ptr [rip + dwords_right]
    movd eax, xmm0
    cmp eax, 3
    jne failure

    vphsubd xmm0, xmm1, xmmword ptr [rip + dwords_right]
    movd eax, xmm0
    cmp eax, 0xffffffff
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
words_left:
    .word 1, 2, 3, 4, 5, 6, 7, 8
words_right:
    .word 5, 6, 7, 8, 9, 10, 11, 12
signed_left:
    .word 0x7fff, 0x7fff, 1, 1, 0, 0, 0, 0
signed_right:
    .word 1, 1, 1, 1, 0, 0, 0, 0
dwords_left:
    .long 1, 2, 3, 4
dwords_right:
    .long 5, 6, 7, 8
