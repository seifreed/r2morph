.intel_syntax noprefix
.global _start
.global twice
.text
# Callee placed before the entry so the call is a backward edge: r2 then analyzes
# twice as its own function and bounds entry0 to _start alone, instead of linear-
# sweeping a contiguous fall-through callee into the entry function.
twice:
    lea  rax, [rdi + rdi]
    ret
# A fully region-reducible function whose only otherwise-unsupported instruction
# is a direct call. Exercises whole-function call virtualization: the VM must
# bridge out to the native callee (twice) with the argument in place, capture
# its return value, keep the relocated stack balanced, and resume. twice stays
# native. Net exit code 42 (= 2 * 21) proves the argument was passed, the callee
# ran and returned, and the result was captured.
_start:
    push rbp
    mov  rbp, rsp
    mov  rdi, 21
    call twice
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall
