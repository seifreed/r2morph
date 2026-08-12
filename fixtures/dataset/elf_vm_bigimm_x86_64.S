.intel_syntax noprefix
.global _start
.text
# Loads a large unsigned 32-bit immediate (high bit set, like a hash/magic
# constant), then masks it. Exercises full-width immediate virtualization: a
# 32-bit constant beyond the signed range must still be accepted. low byte
# 0x2a -> exit code 42.
_start:
    mov eax, 0x8000002a
    and eax, 0xff
    mov edi, eax
    mov eax, 0x3c
    syscall
