.intel_syntax noprefix
.global _start
.text
# The add's flags are dead (overwritten by the cmp before any branch), so the
# add is MBA-folded. Only its VALUE matters: edi=10+5=15 -> cmp passes -> exit 42.
_start:
    mov edi, 10
    add edi, 5
    cmp edi, 15
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
