.intel_syntax noprefix
.global _start
.global twice
.text
# Callee before the entry so it is a distinct function r2 does not fold into
# entry0; reached only through the function pointer in the data slot below.
twice:
    lea  rax, [rdi + rdi]
    ret
.data
# A pointer slot holding the callee address - stands in for a vtable entry / an
# IAT/GOT import slot, the dominant indirect-call shape in real code.
vt:
    .quad twice
.text
# Region-reducible except for two memory-indirect calls: one rip-relative
# (call [rip+vt], the IAT/GOT form) and one base-relative (call [rax], the vtable
# form). The VM must compute each pointer's address, load the callee from memory,
# bridge out with the argument in place and capture the return value.
# Net exit code 42 (= twice(10) + twice(11) = 20 + 22).
_start:
    push rbp
    mov  rbp, rsp
    mov  rdi, 10
    call qword ptr [rip + vt]
    mov  rbx, rax
    mov  rdi, 11
    lea  rax, [rip + vt]
    call qword ptr [rax]
    add  rax, rbx
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall
