.intel_syntax noprefix
.global _start
.text
# Scaled-index packed 128-bit move virtualization (array of vectors): build four
# doubles on the stack and load two 128-bit halves with movups xmm, [base+i*8],
# then add them lane-wise (addpd [20,5] + [22,37] = [42,42]) and truncate the low
# lane. The VM must compute base+index*scale+disp for the packed load. Exit 42.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 32], rax
    mov rax, 0x4014000000000000
    mov [rsp - 24], rax
    mov rax, 0x4036000000000000
    mov [rsp - 16], rax
    mov rax, 0x4042800000000000
    mov [rsp - 8], rax
    lea rbx, [rsp - 32]
    xor rcx, rcx
    movups xmm0, xmmword ptr [rbx + rcx*8]
    mov rcx, 2
    movups xmm1, xmmword ptr [rbx + rcx*8]
    addpd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
