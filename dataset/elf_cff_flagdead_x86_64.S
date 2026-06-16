# CFF flag-liveness fixture (flag-DEAD NOP sled). The `cmp` flags are consumed
# by `je` and nothing downstream of the sled reads flags, so control-flow
# flattening MAY safely overwrite the sled with flag-clobbering dead code.
# edi=0 -> je taken -> exit(0); the obfuscation must preserve that.
.intel_syntax noprefix
.global _start
.text
_start:
    mov edi, 0
    cmp edi, 0
    je after
    mov edi, 5
after:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov eax, 60
    syscall
