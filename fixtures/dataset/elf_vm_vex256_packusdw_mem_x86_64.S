.intel_syntax noprefix
.global _start
.text

# Exercise VEX.256 signed dword to unsigned word saturation with a memory source.
_start:
    vmovdqa ymm0, ymmword ptr [rip + left]
    vpackusdw ymm2, ymm0, ymmword ptr [rip + right]
    vmovdqu ymmword ptr [rsp - 32], ymm2

    mov rax, qword ptr [rsp - 32]
    mov rdx, 0x0004000300020001
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 24]
    mov rdx, 0x0008000700060005
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 16]
    mov rdx, 0xffffffffffff0000
    cmp rax, rdx
    jne failure
    mov rax, qword ptr [rsp - 8]
    mov rdx, 0x000c000b000a0009
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
.p2align 5
left:
    .long 1, 2, 3, 4, -1, 65535, 65536, 70000
right:
    .long 5, 6, 7, 8, 9, 10, 11, 12
