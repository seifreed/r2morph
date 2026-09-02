.intel_syntax noprefix
.global _start
.text

_start:
    lea rbx, [rip + value]
    push word ptr [rbx]
    pop word ptr [rbx + 2]
    movzx edi, word ptr [rbx + 2]
    cmp edi, 0x1234
    jne bad

    mov edi, 42
    jmp done

bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall

.section .data
value:
    .word 0x1234
    .word 0
