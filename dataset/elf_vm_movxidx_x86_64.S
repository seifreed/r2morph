.intel_syntax noprefix
.global _start
.text
# Zero/sign-extends a byte addressed by an unscaled index ([base+index]), then
# branches on the full extended value. Exercises indexed movzx/movsx: movzx of
# 0xd8 -> 216 (>=128), movsx -> -40 (<0). Both correct -> exit 42, else 99.
_start:
    mov eax, 0xd8
    mov [rsp - 16], rax
    lea rbx, [rsp - 16]
    xor rcx, rcx
    movsx rdi, byte ptr [rbx + rcx]
    cmp rdi, 0
    jge wrong
    movzx rsi, byte ptr [rbx + rcx]
    cmp rsi, 128
    jl wrong
    mov rdi, 42
    jmp done
wrong:
    mov rdi, 99
done:
    mov rax, 0x3c
    syscall
