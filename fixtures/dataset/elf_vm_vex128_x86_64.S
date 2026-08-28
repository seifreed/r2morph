.intel_syntax noprefix
.global _start
.global compute
.text
# VEX.128 packed arithmetic: the destination's upper YMM half must be cleared,
# while the operation still computes all four 32-bit lanes in its XMM half.
_start:
    vmovaps ymm0, ymmword ptr [rip + left]
    vmovaps ymm1, ymmword ptr [rip + right]
    vmovaps ymm2, ymmword ptr [rip + offset_vec]
    call compute
    call check_result
    syscall

.section .text.compute,"ax",@progbits
.p2align 4, 0x90
compute:
    vmovaps xmm3, xmm0
    vaddps xmm0, xmm0, xmm1
    vminps xmm0, xmm0, xmm1
    vmaxps xmm0, xmm0, xmm3
    vsubps xmm0, xmm0, xmm2
    vaddps xmm0, xmm0, xmm2
    vmovaps xmm4, xmm0
    vxorps xmm5, xmm3, xmm3
    vorps xmm5, xmm5, xmm3
    vandps xmm5, xmm5, xmm3
    ret

check_result:
    vextractf128 xmm6, ymm5, 1
    movd ecx, xmm6
    test ecx, ecx
    jne .bad_upper
    movd eax, xmm5
    cmp eax, 0x41a00000
    jne .bad_value
    vextractf128 xmm5, ymm4, 1
    movd eax, xmm5
    test eax, eax
    jne .bad_upper
    vcvttss2si eax, xmm4
    cmp eax, 22
    jne .bad_value
    mov edi, 42
    mov eax, 60
    ret
.bad_upper:
    mov edi, 13
    mov eax, 60
    ret
.bad_value:
    mov edi, 14
    mov eax, 60
    ret

.section .rodata
.align 32
left:
    .float 20.0, 5.0, 7.0, 9.0, 100.0, 101.0, 102.0, 103.0
right:
    .float 22.0, 37.0, 3.0, 4.0, 200.0, 201.0, 202.0, 203.0
offset_vec:
    .float 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0
