.intel_syntax noprefix
.global _start
.text
# Rip-relative packed arithmetic virtualization: load a vector and add a packed
# constant vector straight from .rodata (addpd xmm0, [rip+cvecb]: [20,5] +
# [22,37] = [42,42]), then truncate the low lane. The VM must reach the constant
# via a bytecode-base-relative offset and run the packed op. Net exit code 42.
_start:
    movups xmm0, xmmword ptr [rip + cveca]
    addpd xmm0, xmmword ptr [rip + cvecb]
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
.section .rodata
cveca: .double 20.0
       .double 5.0
cvecb: .double 22.0
       .double 37.0
