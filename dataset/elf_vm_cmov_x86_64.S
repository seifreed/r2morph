.intel_syntax noprefix
.global _start
.text
# Two conditional moves. Part 1: a taken 64-bit cmove selects 22 over 20.
# Part 2: a taken 32-bit cmovne must zero-extend (clear the upper 32 bits set in
# RBX). Faithful -> exit 22. A not-taken bug exits 20; a 32-bit move that fails to
# zero-extend leaves RBX's high bit set and exits 99.
_start:
    mov rax, 20
    mov rcx, 22
    mov rdx, 5
    cmp rdx, 5
    cmove rax, rcx
    mov r8, rax
    mov rbx, 0x100000000
    mov ecx, 20
    mov rdx, 5
    cmp rdx, 6
    cmovne ebx, ecx
    shr rbx, 32
    imul rbx, rbx, 77
    add r8, rbx
    mov rdi, r8
    mov rax, 0x3c
    syscall
