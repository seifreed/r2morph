.intel_syntax noprefix
.global _start
.text
# Engine-path packed 128-bit SIMD: the function has a call (region rejects ->
# engine fallback). The run builds two __m128d vectors on the stack, loads them
# with movups (fppload), adds all lanes with addpd (fppacked), and stores the
# result with movups (fppstore) - exercising the engine's packed reg-reg
# arithmetic and 128-bit load/store handlers. It reads out the HIGH lane
# (5.0 + 37.0 = 42.0): a correct packed add gives 42.0 -> (bits>>48)&0xff == 0x45
# == 69, while a scalar (low-lane-only) add would leave the high lane 5.0 -> 0x14
# == 20, so the exit code discriminates packed from scalar.
_start:
    movabs rax, 0x4034000000000000
    mov [rsp - 32], rax
    movabs rax, 0x4014000000000000
    mov [rsp - 24], rax
    movabs rax, 0x4036000000000000
    mov [rsp - 16], rax
    movabs rax, 0x4042800000000000
    mov [rsp - 8], rax
    movups xmm0, xmmword ptr [rsp - 32]
    movups xmm1, xmmword ptr [rsp - 16]
    addpd xmm0, xmm1
    movups xmmword ptr [rsp - 48], xmm0
    mov rax, qword ptr [rsp - 40]
    shr rax, 48
    and rax, 0xff
    mov rdi, rax
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
