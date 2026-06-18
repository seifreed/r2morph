.intel_syntax noprefix
.global _start
.text
# Scalar-FP arithmetic virtualization: materialize 20.0 and 22.0 as double bit
# patterns in the red zone, load them into xmm registers, add them (addsd ->
# 42.0), store the result, and read a distinctive byte of its IEEE-754 encoding
# (42.0 = 0x4045000000000000, so bits [55:48] = 0x45 = 69). A wrong arithmetic
# handler (sub/mul/div, or a corrupt operand) yields a different byte, so this
# fixture discriminates the handler's correctness. Net exit code 69.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 8], rax
    mov rax, 0x4036000000000000
    mov [rsp - 16], rax
    movsd xmm0, qword ptr [rsp - 8]
    movsd xmm1, qword ptr [rsp - 16]
    addsd xmm0, xmm1
    movsd qword ptr [rsp - 24], xmm0
    mov rax, qword ptr [rsp - 24]
    shr rax, 48
    and rax, 0xff
    mov rdi, rax
    mov rax, 0x3c
    syscall
