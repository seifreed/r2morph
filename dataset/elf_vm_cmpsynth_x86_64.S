.intel_syntax noprefix
.global _start
.text
# cmp and test exist only to set flags a branch reads, so the region synthesizes
# their flags (cmp == a-b, test == a&b, both via MBA) instead of running a literal
# cmp/test + pushfq. These branches check the signed comparison (SF vs OF through
# jge) and the zero/sign flags of test, so a wrong synthesis diverts to a non-42
# exit. Net exit code 42 only if every checked flag matches the real CPU.
_start:
    mov  rdi, -5
    cmp  rdi, 3            # -5 < 3 signed: SF != OF, so jge must NOT be taken
    jge  fail1
    mov  rdi, 0
    test rdi, rdi          # zero: ZF set, jnz must NOT be taken
    jnz  fail2
    mov  rdi, 7
    test rdi, rdi          # positive: SF clear, js must NOT be taken
    js   fail3
    mov  rdi, 42
    jmp  done
fail1:
    mov  rdi, 1
    jmp  done
fail2:
    mov  rdi, 2
    jmp  done
fail3:
    mov  rdi, 3
done:
    mov  rax, 0x3c
    syscall
