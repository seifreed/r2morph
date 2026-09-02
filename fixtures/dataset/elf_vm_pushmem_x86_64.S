.intel_syntax noprefix
.global _start
.text

_start:
    lea rbx, [rip + values]
    push qword ptr [rbx]
    pop rax
    mov rdx, 0x1122334455667788
    cmp rax, rdx
    jne bad

    mov ecx, 1
    push qword ptr [rbx + rcx*8]
    pop rax
    mov rdx, 0x8877665544332211
    cmp rax, rdx
    jne bad

    push qword ptr [rip + values + 16]
    pop rax
    mov rdx, 0x0102030405060708
    cmp rax, rdx
    jne bad

    mov edi, 42
    jmp done

bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall

.section .rodata
values:
    .quad 0x1122334455667788
    .quad 0x8877665544332211
    .quad 0x0102030405060708
