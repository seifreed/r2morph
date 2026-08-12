.intel_syntax noprefix
.global _start
.text
# Rip-relative scalar-FP arithmetic virtualization: load an FP constant from
# .rodata and add a second .rodata constant straight from memory (addsd xmm0,
# [rip+c22]: 20.0 + 22.0 = 42.0), then truncate to an int. The VM must reach the
# constant via a bytecode-base-relative offset and run the scalar op against it.
# Net exit code 42.
_start:
    movsd xmm0, qword ptr [rip + c20]
    addsd xmm0, qword ptr [rip + c22]
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
.section .rodata
c20: .double 20.0
c22: .double 22.0
