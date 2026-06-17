.intel_syntax noprefix
.global _start
.text
# Exercises no-base scaled-index lea (lea reg, [index*scale + disp]) — array
# scaling with no base register. Both the bare [idx*8] and the [idx*4+disp]
# forms drive a branch, so a wrong scale/disp would change the exit code.
# Original and virtualized must agree (exit 42 vs 99).
_start:
    mov edi, 7
    lea rax, [rdi*8]            # 7 * 8 = 56
    cmp rax, 56
    jne bad
    mov esi, 3
    lea rdx, [rsi*4 + 0x10]     # 3 * 4 + 16 = 28
    cmp rdx, 28
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
