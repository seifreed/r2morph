.intel_syntax noprefix
.global _start
.text
# Uses lea in both forms: rip-relative (compute a global's address) and
# base+disp (address arithmetic). Exercises lea virtualization: the VM computes
# each address into the destination register without dereferencing, and lea
# sets no flags. *gval(=40) + 2 -> exit code 42.
_start:
    lea rsi, [rip + gval]
    mov rax, [rsi]
    lea rdi, [rax + 2]
    mov rax, 0x3c
    syscall
.data
gval: .quad 40
