.intel_syntax noprefix
.global _start
.text
# Engine-path 32-bit float->int convert, pinning GP-width faithfulness. The
# function has a call (region rejects -> engine fallback). The run loads
# 2147483690.0 (= 2^31 + 42, out of int32 range) and truncates it into edi with
# cvttsd2si (32-bit GP). x86 saturates an out-of-int32 double to 0x80000000, so
# edi = 0x80000000 and the exit code (low byte) is 0. A width-blind handler using
# rax/cvttsd2si would give 2147483690 (0x8000002A), low byte 0x2A = 42 - so this
# fixture discriminates the 32-bit path from the 64-bit one.
_start:
    movabs rax, 0x41e0000005400000
    mov [rsp - 8], rax
    movsd xmm0, qword ptr [rsp - 8]
    cvttsd2si edi, xmm0
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
