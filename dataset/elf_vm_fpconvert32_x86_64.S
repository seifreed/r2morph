.intel_syntax noprefix
.global _start
.text
# 32-bit int<->float conversion: 2147483690.0 = 2^31 + 42 is out of int32 range,
# so a 32-bit cvttsd2si edi saturates to 0x80000000 (exit low byte 0). A VM that
# truncates with 64-bit cvttsd2si rax would give 2147483690 (low byte 42), so this
# fixture pins the 32-bit GP width of the conversion. Net exit code 0.
_start:
    movsd xmm0, qword ptr [rip + cbig]
    cvttsd2si edi, xmm0
    mov rax, 0x3c
    syscall
.section .rodata
cbig: .double 2147483690.0
