.intel_syntax noprefix
.global _start
.text
# A function the control-flow VM rejects (it contains a call) whose straight-line
# run uses an arithmetic-with-memory-source op (add reg, [rsp+disp]). Exercises the
# fallback engine VM's memory-source arithmetic handler. Net exit code 42.
_start:
    mov rdi, 40
    mov [rsp-8], rdi
    mov rax, 2
    mov [rsp-16], rax
    mov rsi, [rsp-8]
    add rsi, [rsp-16]
    mov rdi, rsi
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
