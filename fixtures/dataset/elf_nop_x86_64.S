.intel_syntax noprefix
.global _start
.text
_start:
    mov eax, eax
    mov edi, 42
    mov eax, 60
    syscall
