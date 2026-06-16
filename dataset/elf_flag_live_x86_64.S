# Flag-liveness fixture. `mov rsi, 0` is flag-neutral and preserves the ZF=0 set
# by the preceding `cmp`; the following `jz` reads ZF. Its equivalence group has
# only flag-setting alternatives (xor/sub), so a substitution would set ZF=1, flip
# the branch, and change the exit code from 0 to 1. Instruction substitution must
# refuse the substitution here (flags live, no flag-neutral equivalent available).
.intel_syntax noprefix
.global _start
.text
_start:
    mov ecx, 5
    cmp ecx, 7         # 5 != 7 -> ZF = 0
    mov rsi, 0         # flag-NEUTRAL; preserves ZF = 0 (substitution candidate)
    jz fail            # ZF = 0 -> NOT taken -> exit(0)
    mov edi, 0         # correct path
    jmp do_exit
fail:
    mov edi, 1         # broken path (reached only if flags were clobbered)
do_exit:
    mov eax, 60        # __NR_exit
    syscall
