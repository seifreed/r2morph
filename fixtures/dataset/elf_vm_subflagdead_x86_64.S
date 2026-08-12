.intel_syntax noprefix
.global _start
.text
# The sub's flags are dead (overwritten by cmp before any branch), so it is
# MBA-folded as add a,-b. Only its value matters: 50-8=42 -> cmp passes (42).
_start:
    mov edi, 50
    sub edi, 8
    cmp edi, 42
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
