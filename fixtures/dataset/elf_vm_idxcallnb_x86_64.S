.intel_syntax noprefix
.global _start
.global twice
.text
twice:
    lea rax, [rdi + rdi]
    ret

.data
.align 8
tbl:
    .quad twice

.text
_start:
    push rbp
    mov rbp, rsp
    xor rcx, rcx
    mov rdi, 21
    call qword ptr [tbl + rcx*8]
    mov rdi, rax
    pop rbp
    mov rax, 0x3c
    syscall
