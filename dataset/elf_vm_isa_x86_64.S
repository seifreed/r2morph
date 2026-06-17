.intel_syntax noprefix
.global _start
.text
# Arithmetic/logic mix (shifts, imul, test) reducing to exit code 45,
# single exit. Exercises the VM's extended instruction set.
_start:
    mov edi, 5
    shl edi, 3
    mov eax, 1
    add edi, eax
    mov ecx, 2
    imul ecx, eax
    add edi, ecx
    add edi, 2
    test edi, edi
    jne done
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
