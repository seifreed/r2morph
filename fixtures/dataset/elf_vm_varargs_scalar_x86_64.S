.intel_syntax noprefix
.global _start
.global check_variadic_scalar
.text

# The callee checks the SysV varargs XMM-register count in AL and the first
# variadic double in XMM0. RDTSC keeps this callee native while the caller is
# eligible for whole-function virtualization.
check_variadic_scalar:
    movzx ecx, al
    rdtsc
    cmp ecx, 1
    jne .Lbad
    movq rax, xmm0
    mov rdx, 0x3ff0000000000000
    cmp rax, rdx
    jne .Lbad
    mov eax, 42
    ret
.Lbad:
    xor eax, eax
    ret

_start:
    mov eax, 1
    movsd xmm0, qword ptr [rip + one]
    call check_variadic_scalar
    mov edi, eax
    mov eax, 60
    syscall

.section .rodata
.align 8
one:
    .quad 0x3ff0000000000000
