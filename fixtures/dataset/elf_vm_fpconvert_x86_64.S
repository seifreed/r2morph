.intel_syntax noprefix
.global _start
.text
# int<->float conversion virtualization: convert two integers to doubles, add
# them, and truncate back to an integer (20 -> 20.0, 22 -> 22.0, +, -> 42.0 ->
# 42). Exercises cvtsi2sd (int->float), addsd, and cvttsd2si (float->int) end to
# end with an integer-observable result. A wrong conversion or truncation changes
# the exit code, so this fixture discriminates the handlers. Net exit code 42.
_start:
    mov rax, 20
    cvtsi2sd xmm0, rax
    mov rax, 22
    cvtsi2sd xmm1, rax
    addsd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
