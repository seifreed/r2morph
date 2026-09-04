.intel_syntax noprefix
.global _start
.global atomic_ops
.type atomic_ops, @function
.text
# Locked immediate operations cover direct, RIP-relative, indexed, and absolute
# no-base addressing while preserving memory results and condition flags.
_start:
    lea rbx, [rip + shared]
    call atomic_ops
    cmp dword ptr [rbx], 15
    jne fail
    cmp dword ptr [rbx + 4], 23
    jne fail
    cmp qword ptr [rip + shared_qword], 98
    jne fail
    mov edi, 42
    mov eax, 60
    syscall
fail:
    mov edi, 99
    mov eax, 60
    syscall

atomic_ops:
    lock add dword ptr [rbx], 5
    lock sub qword ptr [rip + shared_qword], 2
    mov rcx, 1
    lock xor dword ptr [rbx + rcx*4], 1
    lock or dword ptr [shared + rcx*4], 2
    ret
.size atomic_ops, .-atomic_ops

.section .data
.align 8
shared:
    .long 10, 20
shared_qword:
    .quad 100
