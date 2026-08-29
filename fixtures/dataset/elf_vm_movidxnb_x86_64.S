.intel_syntax noprefix
.global _start
.text
_start:
    xor rax, rax
    mov rcx, 2
    mov rdx, qword ptr [table + rcx*8]
    mov qword ptr [table + rax*8], rdx
    mov rcx, qword ptr [table + rax*8]
    mov rdi, rcx
    mov rax, 60
    syscall
.data
.align 8
table:
    .quad 35, 0, 35
