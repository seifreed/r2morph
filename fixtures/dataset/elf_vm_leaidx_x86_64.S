.intel_syntax noprefix
.global _start
.text
# Computes an array-element address with a scaled index (base + index*scale),
# then exits with it. Exercises index/scale lea virtualization: the VM scales
# the index, adds the base and displacement, all from frame slots. 10 + 8*4 ->
# exit code 42.
_start:
    mov rbx, 10
    mov rcx, 8
    lea rdi, [rbx + rcx*4]
    mov rax, 0x3c
    syscall
