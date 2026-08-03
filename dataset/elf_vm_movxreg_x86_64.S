.intel_syntax noprefix
.global _start
.text
# Register-source movzx/movsx. Loads a high-bit byte (0xd8) into a register, then
# sign- and zero-extends its LOW BYTE into wider registers and branches on the full
# extended value (the low byte alone cannot tell sign from zero extension). movsx
# must give a negative value, movzx must give 216 (>=128). A 16-bit-source zero-
# extend (cx = 0x8000 -> 32768) exercises the word path. All correct -> exit 42; a
# wrong extension -> exit 99.
_start:
    mov eax, 0xd8
    movsx rdi, al
    cmp rdi, 0
    jge wrong
    movzx rsi, al
    cmp rsi, 128
    jl wrong
    mov ecx, 0x8000
    movzx edx, cx
    cmp edx, 32768
    jne wrong
    mov rdi, 42
    jmp done
wrong:
    mov rdi, 99
done:
    mov rax, 0x3c
    syscall
