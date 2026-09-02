.intel_syntax noprefix
.global _start
.text

# Exercise VEX.128 even-dword signed multiplication and preserve both lanes.
_start:
    movdqa xmm0, xmmword ptr [rip + left]
    movdqa xmm1, xmmword ptr [rip + right]
    vpmuldq xmm2, xmm0, xmm1
    movdqu xmmword ptr [rsp - 16], xmm2
    mov rax, qword ptr [rsp - 16]
    mov rdx, 5
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 8]
    mov rdx, 21
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
left:
    .long 1, 2, 3, 4
right:
    .long 5, 6, 7, 8
