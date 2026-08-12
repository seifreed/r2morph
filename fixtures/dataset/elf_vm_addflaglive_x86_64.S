.intel_syntax noprefix
.global _start
.text
# The add's sign flag IS read by jns, so the add must stay a real flag-setting
# op (NOT MBA'd). edi=10+5=15>0 -> jns taken -> exit 42 (a stale-flag bug -> 99).
_start:
    mov edi, 10
    add edi, 5
    jns positive
    mov edi, 99
    jmp done
positive:
    mov edi, 42
done:
    mov eax, 0x3c
    syscall
