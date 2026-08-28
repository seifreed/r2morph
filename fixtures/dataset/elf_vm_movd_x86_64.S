.intel_syntax noprefix
.global _start
.text
# movd GP->XMM clears the complete upper lane, and XMM->GP zero-extends the dword.
_start:
    mov edi, 42
    movd xmm0, edi
    movups xmmword ptr [rip + result], xmm0
    mov rax, qword ptr [rip + result + 8]
    test rax, rax
    jne fail
    mov edx, dword ptr [rip + result]
    cmp edx, edi
    jne fail
    movd xmm1, edx
    movd esi, xmm1
    cmp esi, edi
    jne fail
    mov eax, 60
    syscall
fail:
    mov edi, 99
    mov eax, 60
    syscall

.section .data
.align 16
result:
    .zero 16
