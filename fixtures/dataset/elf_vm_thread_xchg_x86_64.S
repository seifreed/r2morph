.intel_syntax noprefix
.global _start
.text
# A memory xchg is an implicitly locked atomic exchange on x86. The VM must
# preserve both the old register value and the new memory value.
_start:
    lea rbx, [rip + shared]
    mov rax, 42
    xchg qword ptr [rbx], rax
    mov rcx, 7
    cmp rax, rcx
    jne fail
    mov rcx, qword ptr [rbx]
    cmp rcx, 42
    jne fail
    mov rcx, 1
    mov rax, 84
    xchg qword ptr [rbx + rcx*8], rax
    mov rdx, 11
    cmp rax, rdx
    jne fail
    mov rdx, qword ptr [rbx + rcx*8]
    cmp rdx, 84
    jne fail
    mov edi, 42
    mov eax, 60
    syscall
fail:
    mov edi, 99
    mov eax, 60
    syscall

.section .data
.align 8
shared:
    .quad 7, 11
