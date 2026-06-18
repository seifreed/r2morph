.intel_syntax noprefix
.global _start
.data
arr: .quad 40, 2
.text
# Engine-fallback function (has a call) whose run uses indexed memory:
# add reg, [base+index*8] (array element) and lea reg, [base+index*8]. Exit 42.
_start:
    lea rax, [rip+arr]
    mov rcx, 1
    mov rdi, 40
    add rdi, [rax+rcx*8]
    lea rsi, [rax+rcx*8]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
