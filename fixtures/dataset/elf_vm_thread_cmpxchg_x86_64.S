.intel_syntax noprefix
.global _start
.text
# Locked compare-exchange must preserve success/failure flags, RAX old-value
# semantics, and the selected memory width/addressing form.
_start:
    lea rbx, [rip + shared]
    mov rax, 7
    mov rcx, 42
    lock cmpxchg qword ptr [rbx], rcx
    setne r12b
    mov rdx, qword ptr [rbx]
    cmp rdx, 42
    setne r13b
    mov rdx, 1
    mov rax, 11
    mov rcx, 84
    lock cmpxchg qword ptr [rbx + rdx*8], rcx
    setne r14b
    mov rdx, qword ptr [rbx + rdx*8]
    cmp rdx, 84
    setne r15b
    mov rax, 5
    mov rcx, 99
    lock cmpxchg qword ptr [rbx], rcx
    sete r8b
    mov rdx, 42
    cmp rax, rdx
    setne r9b
    movzx edi, r12b
    movzx eax, r14b
    or edi, eax
    movzx eax, r8b
    or edi, eax
    movzx eax, r9b
    or edi, eax
    movzx eax, r13b
    or edi, eax
    movzx eax, r15b
    or edi, eax
    add edi, 42
    mov eax, 60
    syscall

.section .data
.align 8
shared:
    .quad 7, 11
