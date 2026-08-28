.intel_syntax noprefix
.global _start
.text
_start:
    pxor xmm0, xmm0
    por xmm0, xmm0
    pand xmm0, xmm0
    pandn xmm0, xmm0
    ptest xmm0, xmm0
    jnz .Lbad
    mov edi, 46
    jmp .Lexit
.Lbad:
    mov edi, 99
.Lexit:
    mov eax, 60
    syscall
