.intel_syntax noprefix
.global _start
.text
# A minimal ET_EXEC with PT_INTERP. It has no libc dependency, so the loader
# contract can be exercised without making the fixture host-specific.
_start:
    mov rdi, 30
    add rdi, 20
    sub rdi, 5
    xor rsi, rsi
    mov rax, 60
    syscall
