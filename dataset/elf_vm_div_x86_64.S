.intel_syntax noprefix
.global _start
.text
# div/idiv/cqo virtualized (division - modulo hashing, index math). Unsigned 100/7 =
# 14 rem 2; signed -55/4 via cqo+idiv = -13 (trunc toward 0). The handlers run the
# real division; the explicit xor edx,edx / cqo set up the rdx slot the div reads.
# Exit 42 needs quotient, remainder and sign all correct.
_start:
    mov eax, 100
    xor edx, edx
    mov ecx, 7
    div ecx
    cmp eax, 14
    jne fail
    cmp edx, 2
    jne fail
    mov rax, -55
    cqo
    mov rcx, 4
    idiv rcx
    cmp rax, -13
    jne fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
