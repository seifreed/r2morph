.intel_syntax noprefix
.global _start
.text
# Memory-source FP arithmetic virtualization: store 22.0 to the red zone, convert
# 20 to a double, and add the memory operand (addsd xmm0, [rsp-8] -> 20.0 + 22.0
# = 42.0), then truncate to an int. The VM must compute the operand address from
# the captured rsp and run the scalar op against memory. Net exit code 42.
_start:
    mov rax, 0x4036000000000000
    mov [rsp - 8], rax
    mov rax, 20
    cvtsi2sd xmm0, rax
    addsd xmm0, qword ptr [rsp - 8]
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
