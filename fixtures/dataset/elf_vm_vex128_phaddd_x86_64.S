.intel_syntax noprefix
.global _start
.text

_start:
    movdqa xmm0, xmmword ptr [rip + left_values]
    movdqa xmm1, xmmword ptr [rip + left_values]
    movdqa xmm2, xmmword ptr [rip + right_values]
    vphaddd xmm0, xmm1, xmm2
    movdqu xmmword ptr [rsp - 16], xmm0
    mov rax, qword ptr [rsp - 16]
    mov rdx, 0x0000000700000003
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 8]
    mov rdx, 0x0000000f0000000b
    cmp rax, rdx
    jne failure

    mov eax, 60
    mov edi, 42
    syscall

failure:
    mov eax, 60
    mov edi, 1
    syscall

.section .rodata
.p2align 4
left_values:
    .long 1, 2, 3, 4
right_values:
    .long 5, 6, 7, 8
