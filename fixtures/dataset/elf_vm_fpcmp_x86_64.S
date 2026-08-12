.intel_syntax noprefix
.global _start
.text
# Scalar-FP compare-and-branch virtualization: load 3.0 and 2.0, ucomisd them,
# and branch. 3.0 > 2.0 sets CF=0,ZF=0 so jbe is NOT taken -> exit 42; a wrong
# flag capture would take the branch -> exit 99. The VM must run the real ucomisd
# and route its ZF/PF/CF through the captured-flags slot to the branch handler.
_start:
    mov rax, 0x4008000000000000
    mov [rsp - 8], rax
    mov rax, 0x4000000000000000
    mov [rsp - 16], rax
    movsd xmm0, qword ptr [rsp - 8]
    movsd xmm1, qword ptr [rsp - 16]
    ucomisd xmm0, xmm1
    jbe .Lelse
    mov rdi, 42
    jmp .Lexit
.Lelse:
    mov rdi, 99
.Lexit:
    mov rax, 0x3c
    syscall
