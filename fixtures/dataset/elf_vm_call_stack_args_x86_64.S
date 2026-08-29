.intel_syntax noprefix
.global _start
.global sum_stack_args
.text
# The callee reads two System V stack arguments. The call bridge must restore the
# program stack before pushing its synthetic return address.
sum_stack_args:
    rdtsc
    mov rax, qword ptr [rsp + 8]
    add rax, qword ptr [rsp + 16]
    ret

_start:
    push rbp
    mov rbp, rsp
    push 35
    push 7
    call sum_stack_args
    add rsp, 16
    mov rdi, rax
    leave
    mov eax, 60
    syscall
