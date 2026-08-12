.intel_syntax noprefix
.global _start
.text
# Engine-path scalar-FP load/store: the function contains a call, so the
# whole-function control-flow VM rejects it and the pass falls back to
# virtualizing the straight-line run before the call through the engine VM.
# That run carries a movsd load and store through an xmm register, so it
# exercises the engine's xmm save area and FP memory handlers (not the region's).
# movsd is a verbatim 64-bit move, so the seeded low byte (0x2a) survives the
# round trip xmm save slot -> exit 42. Corrupting the engine FP load or store
# changes the exit code, so the fixture discriminates handler correctness.
_start:
    mov rax, 42
    mov [rsp - 8], rax
    movsd xmm3, qword ptr [rsp - 8]
    movsd qword ptr [rsp - 16], xmm3
    mov rdi, [rsp - 16]
    and rdi, 0xff
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
