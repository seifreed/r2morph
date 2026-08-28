.intel_syntax noprefix
.global _start
.text
# Engine-path no-base scaled-index scalar-FP load. The harmless nop is outside
# the supported region shape, so the straight-line fallback must carry the two
# no-base loads and the FP addition through the engine VM.
_start:
    xor rcx, rcx
    movsd xmm0, qword ptr [rcx*8 + buf]
    mov rcx, 1
    addsd xmm0, qword ptr [rcx*8 + buf]
    cvttsd2si rdi, xmm0
    nop
    mov rax, 0x3c
    syscall
.align 8
buf: .double 20.0
     .double 22.0
