.intel_syntax noprefix
.global _start
.text
# Rip-relative scalar-FP memory virtualization: load an FP constant from .rodata
# (movsd xmm0, [rip+c42]), store it to a .data global (movsd [rip+gout], xmm0),
# load it back, and truncate to an int. The VM must reach the constant and global
# via a bytecode-base-relative offset (their absolute addresses change after the
# code is relocated). Net exit code 42.
_start:
    movsd xmm0, qword ptr [rip + c42]
    movsd qword ptr [rip + gout], xmm0
    movsd xmm1, qword ptr [rip + gout]
    cvttsd2si rdi, xmm1
    mov rax, 0x3c
    syscall
.section .rodata
c42: .double 42.0
.data
gout: .quad 0
