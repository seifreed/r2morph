.intel_syntax noprefix
.global _start
.text
# Scaled-index FP arithmetic virtualization (the accumulation form sum += a[i]):
# build a double array on the stack, load a[0], then add a[1] straight from the
# array (addsd xmm0, [base+index*8]: 20.0 + 22.0 = 42.0) and truncate to an int.
# The VM must compute base+index*scale+disp for the FP add. Net exit code 42.
_start:
    mov rax, 0x4034000000000000
    mov [rsp - 16], rax
    mov rax, 0x4036000000000000
    mov [rsp - 8], rax
    lea rbx, [rsp - 16]
    xor rcx, rcx
    movsd xmm0, qword ptr [rbx + rcx*8]
    mov rcx, 1
    addsd xmm0, qword ptr [rbx + rcx*8]
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
