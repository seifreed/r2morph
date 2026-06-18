.intel_syntax noprefix
.global _start
.text
# A function the whole-function control-flow VM rejects (it contains a call), but
# whose straight-line run mixes register ops with [rsp+disp] memory store/load.
# Exercises the fallback straight-line VM's NEW memory-operand coverage: the run
# stores a register to the red zone and loads it back, all virtualized into the
# engine VM (the region path never reaches this function). Net exit code 42.
_start:
    mov rdi, 50
    mov [rsp-8], rdi
    mov rax, 8
    mov rsi, [rsp-8]
    sub rsi, rax
    mov rdi, rsi
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
