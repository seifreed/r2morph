.intel_syntax noprefix
.global _start
.text
# Engine-path scalar reg-reg FP arithmetic: the function has a call, so the
# whole-function control-flow VM rejects it and the engine virtualizes the
# straight-line run before the call. That run materializes 20.0 and 22.0,
# loads them into xmm via movsd, then addsd xmm0, xmm1 -> 42.0, exercising the
# engine's reg-reg FP arithmetic handler (and the slice-1 load/store). The result
# is stored and its IEEE high byte read out: 42.0 = 0x4045000000000000, so
# (bits >> 48) & 0xff == 0x45 == 69. sub/mul/div would each yield a different
# byte, so the exit code discriminates the operation.
_start:
    movabs rax, 0x4034000000000000
    mov [rsp - 8], rax
    movabs rax, 0x4036000000000000
    mov [rsp - 16], rax
    movsd xmm0, qword ptr [rsp - 8]
    movsd xmm1, qword ptr [rsp - 16]
    addsd xmm0, xmm1
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
