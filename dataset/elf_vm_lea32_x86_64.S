.intel_syntax noprefix
.global _start
.text
# Exercises 32-bit-destination lea (plain and scaled-index). The base address
# exceeds 32 bits, so a 32-bit lea must truncate to the low 32 bits and
# zero-extend; shifting the result down exposes a handler that stored the full
# 64-bit address. Original and virtualized must agree (exit 42 vs 99).
_start:
    mov rdi, 0x100000005        # base beyond 32 bits (movabs)
    lea eax, [rdi+0x3]          # 32-bit lea: low 32 bits = 8, upper zeroed
    shr rax, 4                  # correct -> 0; a 64-bit store -> 0x10000000
    cmp eax, 0
    jne bad
    mov rsi, 0x100000000        # base beyond 32 bits (movabs)
    mov rcx, 2
    lea edx, [rsi+rcx*4]        # 32-bit scaled-index lea: low 32 bits = 8
    shr rdx, 4
    cmp edx, 0
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
