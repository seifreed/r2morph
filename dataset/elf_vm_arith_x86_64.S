.intel_syntax noprefix
.global _start
.text
# Straight-line 64-bit GP-register run (mov/add/sub/xor) whose net effect is
# exit code 45, followed by an exit syscall. Exercises the code-virtualization
# pass: the run is replaced by a trampoline into the generated VM interpreter.
_start:
    mov rdi, 30
    add rdi, 20
    sub rdi, 5
    xor rsi, rsi
    mov rax, 0x3c
    syscall
