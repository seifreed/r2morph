.intel_syntax noprefix
.global _start
.text
# Loads a global through a rip-relative operand, then exits with its value.
# Exercises rip-relative memory virtualization: the VM must reach the global
# (whose absolute address it cannot keep after relocation) via a bytecode-base
# relative offset. Net exit code 42.
_start:
    mov rax, qword ptr [rip + gval]
    mov rdi, rax
    mov rax, 0x3c
    syscall
.data
gval: .quad 42
