.intel_syntax noprefix
.global _start
.text
# 8-bit register compare/test virtualized - the byte terminator of a char loop
# (`test al, al; jz`) and a byte equality (`cmp dl, bl; jne`). The byte values are
# set with 32-bit movs (already virtualized) so only the 8-bit test/cmp exercise the
# new width. Exit 42 requires both 8-bit flag results correct; a wrong 8-bit ZF/SF
# synthesis diverges to 99.
_start:
    mov eax, 5
    test al, al
    jz fail
    mov edx, 7
    mov ebx, 7
    cmp dl, bl
    jne fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
