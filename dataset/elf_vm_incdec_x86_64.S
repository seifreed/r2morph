.intel_syntax noprefix
.global _start
.text
# Sets the carry flag with a compare, then inc (which must preserve CF, unlike
# add by one), then branches on CF. Exercises inc/dec virtualization including
# the flag invariant: if inc clobbered CF the branch would miss. CF stays set
# -> exit code 42 (a broken inc would exit 99).
_start:
    mov rax, 1
    mov rdi, 5
    cmp rax, 2
    inc rdi
    jc carry_set
    mov rdi, 99
    jmp done
carry_set:
    mov rdi, 42
done:
    mov rax, 0x3c
    syscall
