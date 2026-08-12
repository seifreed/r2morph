.intel_syntax noprefix
.global _start
.text
# Accumulates a register into a memory location in place (read-modify-write),
# then exits with the stored sum. Exercises memory-destination arithmetic
# virtualization: the VM computes the address and applies the real op directly
# against memory, capturing flags. 30 + 12 -> exit code 42.
_start:
    mov rax, 30
    mov [rsp - 8], rax
    mov rdi, 12
    add [rsp - 8], rdi
    mov rdi, [rsp - 8]
    mov rax, 0x3c
    syscall
