.intel_syntax noprefix
.global _start
.text
# Straight-line 32-bit GP-register run (eax/edi). Net effect: exit code 45.
# Exercises the code-virtualization pass's 32-bit (zero-extending) handlers.
_start:
    mov edi, 30
    add edi, 20
    sub edi, 5
    and edi, 0xff
    mov eax, 0x3c
    syscall
