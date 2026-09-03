.intel_syntax noprefix
.global _start
.text

# Exercise VEX.128 variable packed shifts and alternating add/subtract.
_start:
    movdqa xmm0, xmmword ptr [rip + integer_values]
    movdqa xmm1, xmmword ptr [rip + shift_counts]
    vpsllvd xmm2, xmm0, xmm1
    movdqu xmmword ptr [rsp - 16], xmm2
    mov rax, qword ptr [rsp - 16]
    mov rdx, 0x0000000400000002
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 8]
    mov rdx, 0x0000000800000006
    cmp rax, rdx
    jne failure

    movaps xmm0, xmmword ptr [rip + float_left]
    movaps xmm1, xmmword ptr [rip + float_right]
    vaddsubps xmm2, xmm0, xmm1
    movdqu xmmword ptr [rsp - 16], xmm2
    mov rax, qword ptr [rsp - 16]
    mov rdx, 0x41b0000041100000
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 8]
    mov rdx, 0x4220000041d80000
    cmp rax, rdx
    jne failure

    mov eax, 60
    mov edi, 42
    syscall

failure:
    mov eax, 60
    mov edi, 1
    syscall

.section .rodata
.p2align 4
integer_values:
    .long 1, 2, 3, 4
shift_counts:
    .long 1, 1, 1, 1
float_left:
    .long 0x41200000, 0x41a00000, 0x41f00000, 0x42200000
float_right:
    .long 0x3f800000, 0x40000000, 0x40400000, 0x40800000
