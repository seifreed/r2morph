.intel_syntax noprefix
.global _start
.data
gval: .quad 42
.text
# A function the control-flow VM rejects (it contains a call) whose straight-line
# run reads a global via mov reg, [rip+gval]. Exercises the fallback engine VM's
# rip-relative load handler (the global is reached from the bytecode base plus a
# stored signed offset, base-independently). Net exit code 42.
_start:
    mov rax, 0
    mov rdi, [rip+gval]
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
