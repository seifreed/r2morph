.intel_syntax noprefix
.global _start
.text
# bt (bit test) virtualized - sets CF from the selected bit, leaves ZF unchanged.
# bit 3 of 0x08 is 1 (register index, jnc not taken); bit 5 of 0x08 is 0 (immediate
# index, jc not taken); a ZF set before `bt rbx, 8` must survive it (the handler
# merges CF into the flags slot, keeping ZF). Exit 42 needs all three.
_start:
    mov eax, 0x08
    mov ecx, 3
    bt eax, ecx
    jnc fail
    mov edx, 0x08
    bt edx, 5
    jc fail
    xor esi, esi
    mov rbx, 0x100
    bt rbx, 8
    jnz fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
