.intel_syntax noprefix
.global _start
.text
# Zero- and sign-extends a high-bit byte (0xd8) from memory, then branches on
# the full extended value. Exercises movzx/movsx virtualization: movzx must
# give 216 (>=128), movsx must give -40 (<0). Both correct -> exit 42; a wrong
# extension would exit 99.
_start:
    mov eax, 0xd8
    mov [rsp - 8], rax
    movsx rdi, byte ptr [rsp - 8]
    cmp rdi, 0
    jge wrong
    movzx rsi, byte ptr [rsp - 8]
    cmp rsi, 128
    jl wrong
    mov rdi, 42
    jmp done
wrong:
    mov rdi, 99
done:
    mov rax, 0x3c
    syscall
