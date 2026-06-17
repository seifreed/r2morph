.intel_syntax noprefix
.global _start
.text
# Register run that stores to and loads from the stack red zone (rsp-relative,
# no rsp modification, no call). Exercises memory-operand virtualization:
# the VM must compute [rsp-8] from the captured original rsp. Net exit code 42.
_start:
    mov rdi, 42
    mov [rsp - 8], rdi
    mov rsi, [rsp - 8]
    mov rdi, rsi
    mov rax, 0x3c
    syscall
