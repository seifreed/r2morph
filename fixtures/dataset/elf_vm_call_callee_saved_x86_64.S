.intel_syntax noprefix
.global _start
.text

# The native callee observes the System V callee-saved register contract. A call
# bridge that leaves interpreter state in these registers returns 1 instead of 79.
check_callee_saved:
    mov rax, rbx
    mov rdx, 0x1122334455667788
    cmp rax, rdx
    jne .Lbad
    mov rax, rbp
    mov rdx, 0x2233445566778899
    cmp rax, rdx
    jne .Lbad
    mov rax, r12
    mov rdx, 0x33445566778899aa
    cmp rax, rdx
    jne .Lbad
    mov rax, r13
    mov rdx, 0x445566778899aabb
    cmp rax, rdx
    jne .Lbad
    mov rax, r14
    mov rdx, 0x5566778899aabbcc
    cmp rax, rdx
    jne .Lbad
    mov rax, r15
    mov rdx, 0x66778899aabbccdd
    cmp rax, rdx
    jne .Lbad
    mov eax, 79
    ret

.Lbad:
    mov eax, 1
    ret

.globl _start
_start:
    mov rbx, 0x1122334455667788
    mov rbp, 0x2233445566778899
    mov r12, 0x33445566778899aa
    mov r13, 0x445566778899aabb
    mov r14, 0x5566778899aabbcc
    mov r15, 0x66778899aabbccdd
    lea rax, [rip + check_callee_saved]
    call rax
    mov edi, eax
    mov eax, 60
    syscall
