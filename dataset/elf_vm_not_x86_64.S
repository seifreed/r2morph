.intel_syntax noprefix
.global _start
.text
# `not reg` virtualized (bitwise complement, no flags - common in decode/obfuscation).
# 32-bit `not eax` zero-extends (0x0F -> 0xFFFFFFF0, low byte 0xF0); 64-bit `not rbx`
# of 0 is -1; 8-bit `not dl` on edx=0x1200 flips only dl -> edx=0x12FF (upper bytes
# preserved). Exit 42 needs all three widths correct.
_start:
    mov eax, 0x0F
    not eax
    and eax, 0xFF
    cmp eax, 0xF0
    jne fail
    mov rbx, 0
    not rbx
    cmp rbx, -1
    jne fail
    mov edx, 0x1200
    not dl
    cmp edx, 0x12FF
    jne fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
