.intel_syntax noprefix
.global _start
.text
# The callee reads the seventh integer argument from the native call stack and
# leaves ZF set for the caller's immediate conditional branch.
check_stack_argument:
    cmp qword ptr [rsp+8], 0x1234
    ret

.globl _start
_start:
    push 0x1234
    mov rax, offset check_stack_argument
    call rax
    je .Lgood
    add rsp, 8
    mov edi, 1
    jmp .Lexit

.Lgood:
    add rsp, 8
    mov edi, 73

.Lexit:
    mov eax, 60
    syscall
