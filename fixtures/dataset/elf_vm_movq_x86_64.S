.intel_syntax noprefix
.global _start
.text
# movq xmm,xmm copies the low qword and clears the high qword. The high lane
# check makes a scalar movsd-style implementation observably incorrect.
_start:
    movups xmm0, xmmword ptr [rip + source]
    movq xmm1, xmm0
    movups xmmword ptr [rip + result], xmm1
    mov rdi, qword ptr [rip + result + 8]
    test rdi, rdi
    jne fail
    mov edi, dword ptr [rip + result]
    mov eax, 60
    syscall
fail:
    mov edi, 99
    mov eax, 60
    syscall

.section .data
.align 16
source:
    .quad 42
    .quad 0x1122334455667788
result:
    .zero 16
