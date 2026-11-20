.intel_syntax noprefix
.global _start
.text
_start:
    mov rax, rax
    mov edi, 42
    mov eax, 60
    syscall
