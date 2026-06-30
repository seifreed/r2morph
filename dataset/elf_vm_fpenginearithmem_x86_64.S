.intel_syntax noprefix
.global _start
.text
# Engine-path scalar FP arithmetic with a memory source: the function has a call
# (region rejects -> engine fallback). The run loads 20.0 into xmm0 and adds
# 22.0 straight from memory (addsd xmm0, [rsp-16]), exercising the engine's
# memory-source FP arithmetic handler. The result 42.0 is stored and its IEEE
# high byte read out: (bits >> 48) & 0xff == 0x45 == 69; sub/mul/div differ.
_start:
    movabs rax, 0x4034000000000000
    mov [rsp - 8], rax
    movabs rax, 0x4036000000000000
    mov [rsp - 16], rax
    movsd xmm0, qword ptr [rsp - 8]
    addsd xmm0, qword ptr [rsp - 16]
    movsd qword ptr [rsp - 24], xmm0
    mov rax, qword ptr [rsp - 24]
    shr rax, 48
    and rax, 0xff
    mov rdi, rax
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
