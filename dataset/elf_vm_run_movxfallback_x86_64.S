.intel_syntax noprefix
.global _start
.text
# Engine-fallback function (has a call) whose run uses movzx/movsx of a byte from
# [rsp+disp]. Exercises the fallback engine VM's byte/word extend handlers.
# Net exit code 42.
_start:
    mov rax, 0x2a
    mov [rsp-8], rax
    movzx rdi, byte ptr [rsp-8]
    movsx rsi, byte ptr [rsp-8]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
