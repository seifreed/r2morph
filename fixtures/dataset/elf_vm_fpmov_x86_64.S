.intel_syntax noprefix
.global _start
.text
# Register-register xmm move virtualization: convert 21 to a double, copy it with
# movaps (full 128-bit copy) and movsd (scalar reg-reg copy), add the copies
# (21.0 + 21.0 = 42.0), and truncate to an int. A broken xmm-xmm move would feed
# the wrong value into the add. Net exit code 42.
_start:
    mov rax, 21
    cvtsi2sd xmm0, rax
    movaps xmm2, xmm0
    movsd xmm1, xmm2
    addsd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
