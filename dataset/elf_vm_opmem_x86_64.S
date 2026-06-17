.intel_syntax noprefix
.global _start
.text
# Adds an rsp-relative memory operand and then a rip-relative global into a
# register. Exercises both arithmetic-with-memory forms (base+disp and
# rip-relative): the VM computes each address, applies the real op against
# memory, writes back, and captures flags. 12 + 20 + 10 -> exit code 42.
_start:
    mov rax, 20
    mov [rsp - 8], rax
    mov rdi, 12
    add rdi, [rsp - 8]
    add rdi, qword ptr [rip + gval]
    mov rax, 0x3c
    syscall
.data
gval: .quad 10
