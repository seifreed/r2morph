.intel_syntax noprefix
.global _start
.text
# push imm round-trips: a positive imm and a sign-extended negative imm. A
# handler that zero-extended the immediate would fail the -1 check (42 vs 99).
_start:
    push 0x7fffffff
    pop rax
    cmp rax, 0x7fffffff
    jne bad
    push -1
    pop rcx
    cmp rcx, -1
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
