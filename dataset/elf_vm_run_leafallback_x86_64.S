.intel_syntax noprefix
.global _start
.text
# A function the control-flow VM rejects (it contains a call) whose straight-line
# run uses lea reg, [base+disp]. Exercises the fallback engine VM's lea handler
# (computes the address into the destination, no dereference). Net exit code 42.
_start:
    mov rax, 40
    lea rdi, [rax+2]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
