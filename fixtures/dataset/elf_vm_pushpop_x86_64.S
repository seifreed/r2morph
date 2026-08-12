.intel_syntax noprefix
.global _start
.text
# Balanced register-save bracket (3 pushes deep, so a naive in-frame stack would
# march into the spilled context/flags) plus a 64-bit push/pop round-trip. The
# saved values are clobbered then restored and checked; a collision or a width
# bug changes the exit code (42 vs 99).
_start:
    mov ebx, 0x11
    mov r12d, 0x22
    mov r13d, 0x33
    push rbx
    push r12
    push r13
    mov ebx, 0
    mov r12d, 0
    mov r13d, 0
    pop r13
    pop r12
    pop rbx
    cmp ebx, 0x11
    jne bad
    cmp r12d, 0x22
    jne bad
    cmp r13d, 0x33
    jne bad
    mov rax, 0x1122334455667788
    push rax
    pop rdx
    cmp rdx, rax
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
