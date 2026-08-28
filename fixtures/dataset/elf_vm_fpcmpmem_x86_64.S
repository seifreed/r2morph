.intel_syntax noprefix
.global _start
.text
_start:
    lea rax, [rip + scalar_double]
    movsd xmm0, qword ptr [rax]
    ucomisd xmm0, qword ptr [rax]
    jne .Lbad
    lea rax, [rip + scalar_float]
    movss xmm1, dword ptr [rax]
    ucomiss xmm1, dword ptr [rax]
    jne .Lbad
    mov edi, 44
    jmp .Lexit
.Lbad:
    mov edi, 99
.Lexit:
    mov eax, 60
    syscall

.section .rodata
.p2align 3
scalar_double:
    .quad 0x4008000000000000
scalar_float:
    .long 0x3fc00000
