# CFF flag-liveness fixture (flag-LIVE NOP sled). A reachable NOP sled sits
# between a flag-setting `cmp` and a flag-consuming `je`, so the flags are live
# across the sled. Control-flow flattening must NOT overwrite this sled with
# flag-clobbering dead code (doing so flips the branch). edi=3 -> cmp edi,5 sets
# ZF=0 -> je not taken -> exit(7).
.intel_syntax noprefix
.global _start
.text
_start:
    mov edi, 3
    cmp edi, 5
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    je equal
    mov edi, 7
    jmp done
equal:
    mov edi, 9
done:
    mov eax, 60
    syscall
