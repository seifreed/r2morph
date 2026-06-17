.intel_syntax noprefix
.global _start
.text
# Compares a register against a value held in memory (rsp-relative); the branch
# it drives selects the exit code. Exercises cmp-with-memory virtualization:
# the VM must compute the address, run the real cmp, and capture its flags.
# Equal path -> exit 42; a wrong comparison would exit 99.
_start:
    mov rax, 7
    mov [rsp - 16], rax
    mov rdi, 7
    cmp rdi, [rsp - 16]
    jne notequal
    mov rdi, 42
    jmp done
notequal:
    mov rdi, 99
done:
    mov rax, 0x3c
    syscall
