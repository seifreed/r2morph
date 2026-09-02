.intel_syntax noprefix
.global _start
.text

_start:
    lea rbx, [rip + values]
    mov rax, 0x1122334455667788
    push rax
    pop qword ptr [rbx]
    mov rax, qword ptr [rbx]
    mov rdx, 0x1122334455667788
    cmp rax, rdx
    jne bad

    mov ecx, 1
    mov rax, 0x8877665544332211
    push rax
    pop qword ptr [rbx + rcx*8]
    mov rax, qword ptr [rbx + rcx*8]
    mov rdx, 0x8877665544332211
    cmp rax, rdx
    jne bad

    mov rax, 0x0102030405060708
    push rax
    pop qword ptr [rip + values + 16]
    mov rax, qword ptr [rip + values + 16]
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

.section .data
values:
    .quad 0
    .quad 0
    .quad 0
