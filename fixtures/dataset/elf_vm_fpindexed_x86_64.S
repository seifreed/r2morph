.intel_syntax noprefix
.global _start
.text
# Scaled-index FP memory virtualization (array-of-double access): build a small
# double array on the stack, then load two elements with movsd xmm, [base+idx*8],
# add them (20.0 + 22.0 = 42.0) and truncate to an int. The VM must compute
# base+index*scale+disp for the FP load. Net exit code 42.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 16], rax
    mov rax, 0x4036000000000000
    mov [rsp - 8], rax
    lea rbx, [rsp - 16]
    xor rcx, rcx
    movsd xmm0, qword ptr [rbx + rcx*8]
    mov rcx, 1
    movsd xmm1, qword ptr [rbx + rcx*8]
    addsd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
