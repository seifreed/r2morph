.intel_syntax noprefix
.global _start
.text
# 16-bit word ops virtualized (WORD/wide-char code). `cmp ax, cx` equal -> ZF (je);
# `inc dx` wraps 0xFFFF->0 -> ZF (jnz not taken, 16-bit synthesis); `inc bx` with
# ebx=0x00FF0000 must yield ebx=0x00FF0001 (the handler merges the low word over the
# preserved upper 48 bits). Byte/word values set via 32-bit movs. Exit 42 needs all.
_start:
    mov eax, 0x1234
    mov ecx, 0x1234
    cmp ax, cx
    jne fail
    mov edx, 0xFFFF
    inc dx
    jnz fail
    mov ebx, 0x00FF0000
    inc bx
    cmp ebx, 0x00FF0001
    jne fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
