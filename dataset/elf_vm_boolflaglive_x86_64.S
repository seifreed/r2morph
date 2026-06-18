.intel_syntax noprefix
.global _start
.text
# Flag-LIVE boolean ops (a branch reads their flags): the region routes them to
# the synthesizing handler too (result via boolean MBA, flags synthesized with
# CF=OF=0 in logic mode). The branches check the zero flag of and/xor and the
# sign flag of or, so a wrong synthesis diverts to a non-42 exit.
_start:
    mov  rdi, 0xff
    and  rdi, 0x0f          # 0x0f nonzero: ZF clear, jz must NOT jump
    jz   fail1
    mov  rdi, 5
    xor  rdi, 5             # 0: ZF set, jnz must NOT jump
    jnz  fail2
    movabs rdi, 0x8000000000000000
    or   rdi, 1             # negative: SF set, jns must NOT jump
    jns  fail3
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
