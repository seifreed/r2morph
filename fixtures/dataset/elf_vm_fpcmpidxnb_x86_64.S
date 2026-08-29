.intel_syntax noprefix
.global _start
.text

# Scalar FP compare with an absolute no-base indexed source.
_start:
    mov rax, 0x3ff0000000000000
    mov [rsp - 8], rax
    movsd xmm0, qword ptr [rsp - 8]
    mov rcx, 1
    ucomisd xmm0, qword ptr [table + rcx*8]
    jne .Lbad
    mov edi, 1
    jmp .Lexit
.Lbad:
    mov edi, 0
.Lexit:
    mov eax, 60
    syscall

.data
.align 16
table:
    .quad 0, 0x3ff0000000000000
