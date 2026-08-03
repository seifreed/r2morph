.intel_syntax noprefix
.global _start
.text
# cmp sets ZF; `sete al` writes AL only, so RAX's upper bytes must be preserved.
# Faithful setcc -> exit 171 (1 from the set result + 170 from the preserved
# byte1 0xAA). A whole-register overwrite would exit 1; an inverted condition 170.
_start:
    mov rax, 0xAA05
    mov rcx, 5
    cmp rcx, 5
    sete al
    mov rdi, rax
    and rdi, 0xff
    mov rdx, rax
    shr rdx, 8
    and rdx, 0xff
    add rdi, rdx
    mov rax, 0x3c
    syscall
