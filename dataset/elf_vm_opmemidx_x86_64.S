.intel_syntax noprefix
.global _start
.text
# Adds an array element addressed by a scaled index into a register. Exercises
# indexed memory-source arithmetic virtualization: the VM computes base +
# index*scale, reads memory there, and applies the real op. arr[1]=32, 10 + 32
# -> exit code 42.
_start:
    mov rax, 10
    mov [rsp - 32], rax
    mov rax, 32
    mov [rsp - 24], rax
    lea rbx, [rsp - 32]
    mov rcx, 1
    mov rdi, 10
    add rdi, [rbx + rcx*8]
    mov rax, 0x3c
    syscall
