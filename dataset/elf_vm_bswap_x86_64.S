.intel_syntax noprefix
.global _start
.text
# `bswap reg` virtualized (byte-order reversal, no flags - endian/hash code). 32-bit
# bswap of 0x12345678 is 0x78563412 (zero-extends); 64-bit bswap of
# 0x1122334455667788 is 0x8877665544332211 (low byte 0x11). Exit 42 needs both.
_start:
    mov eax, 0x12345678
    bswap eax
    cmp eax, 0x78563412
    jne fail
    mov rbx, 0x1122334455667788
    bswap rbx
    and ebx, 0xFF
    cmp ebx, 0x11
    jne fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
