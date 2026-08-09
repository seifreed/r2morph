.intel_syntax noprefix
.global _start
.text
# 8-bit inc/dec virtualized. `inc al` with eax=0x1200 must yield eax=0x1201 - the
# handler merges the low byte back over the preserved upper bytes; a whole-cell
# write would drop 0x12__ and fail the 32-bit cmp. `inc dl` with dl=0xFF wraps to 0
# and must set ZF (8-bit synthesis); a wrong 8-bit ZF takes jnz. Exit 42 needs both.
_start:
    mov eax, 0x1200
    inc al
    cmp eax, 0x1201
    jne fail
    mov edx, 0xFF
    inc dl
    jnz fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
