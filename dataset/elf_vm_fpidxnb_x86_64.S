.intel_syntax noprefix
.global _start
.text
# No-base scaled-index scalar-FP load virtualization: a static (non-PIE) binary
# addresses a global array with index*scale plus an absolute displacement and no
# base register. Load two pre-initialized doubles with movsd xmm, [index*8 + buf]
# and add them (20.0 + 22.0 = 42.0), then truncate. The VM computes
# index*scale+disp with no base register. Net exit code 42.
_start:
    xor rcx, rcx
    movsd xmm0, qword ptr [rcx*8 + buf]
    mov rcx, 1
    movsd xmm1, qword ptr [rcx*8 + buf]
    addsd xmm0, xmm1
    cvttsd2si rdi, xmm0
    mov rax, 0x3c
    syscall
.data
buf: .double 20.0
     .double 22.0
