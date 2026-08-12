.intel_syntax noprefix
.global _start
.text
# Engine-path int<->float conversion: the function has a call, so the region
# rejects it and the engine virtualizes the straight-line run before the call.
# That run converts the integer 42 to a double (cvtsi2sd) and back (cvttsd2si),
# exercising the engine's 64-bit int<->float convert handlers. The value
# round-trips to 42 -> exit 42; a width-faithful handler is required.
_start:
    mov rax, 42
    cvtsi2sd xmm0, rax
    cvttsd2si rdi, xmm0
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
