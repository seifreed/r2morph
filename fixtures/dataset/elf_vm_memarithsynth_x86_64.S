.intel_syntax noprefix
.global _start
.text
# A flag-live arith-with-memory op: add reg, [mem] then branch on the zero flag.
# The handler computes reg+[mem] via MBA and synthesizes the flags (no literal op,
# no pushfq), so a wrong result or ZF synthesis diverts to a non-42 exit.
.data
val:
    .quad -7
.text
_start:
    mov  rdi, 7
    add  rdi, qword ptr [rip + val]   # 7 + (-7) = 0: ZF set, jnz must NOT jump
    jnz  fail1
    mov  rsi, 100
    sub  rsi, qword ptr [rip + val]   # 100 - (-7) = 107: result, SF clear
    js   fail2
    mov  rdi, 42
    jmp  done
fail1:
    mov  rdi, 1
    jmp  done
fail2:
    mov  rdi, 2
done:
    mov  rax, 0x3c
    syscall
