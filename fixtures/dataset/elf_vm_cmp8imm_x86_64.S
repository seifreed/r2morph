.intel_syntax noprefix
.global _start
.text
# 8-bit immediate compare virtualized - the byte classify `cmp al, 0x30` a char
# routine uses. al='A'(0x41): `cmp al, 0x41` sets ZF (equal, je-not-fail); `cmp al,
# 0x30` leaves CF=0 (0x41 >= 0x30, jb-not-fail). Exit 42 requires the 1-byte
# immediate read and the 8-bit ZF/CF synthesis to be correct; either diverges to 99.
_start:
    mov eax, 0x41
    cmp al, 0x41
    jne fail
    cmp al, 0x30
    jb fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
