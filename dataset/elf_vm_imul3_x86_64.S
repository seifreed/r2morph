.intel_syntax noprefix
.global _start
.text
# Exercises three-operand imul (reg, reg, imm) virtualization in both 32- and
# 64-bit forms, using only 32-bit-immediate movs so the whole function stays
# reducible. The 64-bit product overflows 32 bits (checked by shifting the high
# word down), so a handler that truncated to 32 bits or mishandled the immediate
# width would diverge; original and virtualized must agree (exit 42 vs 99).
_start:
    mov esi, 0x1234
    imul eax, esi, 0x100        # 32-bit: 0x1234 * 0x100 = 0x123400
    cmp eax, 0x123400
    jne bad
    mov esi, 0x40000000         # zero-extends into rsi (32-bit immediate)
    imul rax, rsi, 0x10         # 64-bit: 0x40000000 * 0x10 = 0x400000000
    shr rax, 32                 # high word = 0x4 (0 if the product was truncated)
    cmp eax, 0x4
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
