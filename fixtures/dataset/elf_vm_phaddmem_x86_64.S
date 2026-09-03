.intel_syntax noprefix
.global _start
.text
_start:
    lea rsi, [rip + left]
    lea rdi, [rip + right]
    lea rdx, [rip + output]
    movdqu xmm0, [rsi]
    phaddw xmm0, [rdi]
    movdqu [rdx], xmm0
    movzx edi, word ptr [rdx]
    mov eax, 60
    syscall
.section .rodata
.align 16
left:
    .short 1, 2, 3, 4, 5, 6, 7, 8
right:
    .short 10, 20, 30, 40, 50, 60, 70, 80
.bss
.align 16
output:
    .zero 16
