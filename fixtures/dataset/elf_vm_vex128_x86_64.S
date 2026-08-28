.intel_syntax noprefix
.global _start
.text
# VEX.128 packed arithmetic: the destination's upper YMM half must be cleared,
# while the operation still computes all four 32-bit lanes in its XMM half.
_start:
    vmovaps ymm0, ymmword ptr [rip + left]
    vmovaps ymm1, ymmword ptr [rip + right]
    vmovaps ymm2, ymmword ptr [rip + offset_vec]
    vaddps xmm0, xmm0, xmm1
    vsubps xmm0, xmm0, xmm2
    call check_result
    mov edi, eax
    mov eax, 60
    syscall

check_result:
    vextractf128 xmm3, ymm0, 1
    movd eax, xmm3
    test eax, eax
    jne .bad_upper
    vcvttss2si eax, xmm0
    cmp eax, 41
    jne .bad_value
    mov eax, 42
    ret
.bad_upper:
    mov eax, 13
    ret
.bad_value:
    mov eax, 14
    ret

.section .rodata
.align 32
left:
    .float 20.0, 5.0, 7.0, 9.0, 100.0, 101.0, 102.0, 103.0
right:
    .float 22.0, 37.0, 3.0, 4.0, 200.0, 201.0, 202.0, 203.0
offset_vec:
    .float 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0
