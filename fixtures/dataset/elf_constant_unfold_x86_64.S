.intel_syntax noprefix
.global _start
.text
# The zeroing move is intentionally five bytes so ConstantUnfolding can replace
# it with an equivalent shorter sequence. The binary exits with 42.
_start:
    mov edi, 0
    add edi, 42
    mov eax, 60
    syscall
