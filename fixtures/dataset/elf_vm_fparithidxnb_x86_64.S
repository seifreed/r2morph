.intel_syntax noprefix
.global _start
.text
# Scalar FP arithmetic with an absolute no-base indexed source. The accumulator
# starts at 20.0 and adds table[1] (22.0), so the native exit code is 42.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 8], rax
    movsd xmm0, qword ptr [rsp - 8]
    mov rcx, 1
    addsd xmm0, qword ptr [table + rcx*8]
    cvttsd2si rdi, xmm0
    mov eax, 60
    syscall
.data
.align 16
table:
    .quad 0x0000000000000000, 0x4036000000000000
