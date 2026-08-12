.intel_syntax noprefix
.global _start
.global twice
.text
# Callee before the entry so the call site is a backward edge: r2 then analyzes
# twice as its own function instead of sweeping it into entry0.
twice:
    lea  rax, [rdi + rdi]
    ret
# Fully region-reducible except for one register-indirect call. The target is
# materialized into rax (lea rip-relative) and then called through the register,
# so the VM must read the call target from rax's frame slot at runtime, bridge
# out to the native callee with the argument in place, and capture the return
# value. Net exit code 42 (= 2 * 21).
_start:
    push rbp
    mov  rbp, rsp
    lea  rax, [rip + twice]
    mov  rdi, 21
    call rax
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall
