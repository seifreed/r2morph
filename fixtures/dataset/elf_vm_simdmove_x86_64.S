.intel_syntax noprefix
.global _start
.text
# movdqu transfers all 128 bits without requiring alignment; the register move
# must preserve both qwords before the result is checked through memory.
_start:
    movdqu xmm0, xmmword ptr [rip + source]
    movdqa xmm1, xmm0
    movdqu xmmword ptr [rip + result], xmm1
    mov rdi, qword ptr [rip + result]
    cmp rdi, qword ptr [rip + source]
    jne fail
    mov rdi, qword ptr [rip + result + 8]
    cmp rdi, qword ptr [rip + source + 8]
    jne fail
    mov edi, 42
    mov eax, 60
    syscall
fail:
    mov edi, 99
    mov eax, 60
    syscall

.section .data
.align 16
source:
    .quad 0x1122334455667788
    .quad 0x8877665544332211
result:
    .zero 16
