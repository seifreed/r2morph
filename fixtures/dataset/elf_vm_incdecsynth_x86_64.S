.intel_syntax noprefix
.global _start
.text
# inc/dec preserve CF and set OF/SF/ZF/PF. The synthesizing handler computes the
# result by MBA and synthesizes OF/SF/ZF/PF while carrying CF over unchanged. The
# branches check dec's zero flag (jnz) and that inc preserves the carry a prior
# cmp set (jnc), so a wrong synthesis or a clobbered CF diverts to a non-42 exit.
_start:
    mov  rdi, 1
    dec  rdi             # 1 - 1 = 0: ZF set, jnz must NOT jump
    jnz  fail1
    mov  rsi, 10
    cmp  rsi, 20         # 10 < 20 unsigned: CF (borrow) set
    inc  rsi             # rsi=11, CF must be preserved (=1)
    jnc  fail2
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
