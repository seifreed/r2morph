.intel_syntax noprefix
.global _start
.data
barr: .byte 10, 42, 99
.text
# Engine-fallback function (has a call) whose run does movzx reg, byte [base+index]
# (indexed byte extend from an array). Net exit code 42.
_start:
    lea rax, [rip+barr]
    mov rcx, 1
    movzx rdi, byte ptr [rax+rcx]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
