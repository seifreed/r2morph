.intel_syntax noprefix
.global _start
.data
gval: .quad 10
.text
# Engine-fallback function (has a call) whose run uses rip-relative arithmetic
# (add reg, [rip+g]) and rip-relative lea (lea reg, [rip+g]). Net exit code 42.
_start:
    mov rdi, 32
    add rdi, [rip+gval]
    lea rsi, [rip+gval]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
