.intel_syntax noprefix
.global _start
.text
# Rip-relative packed 128-bit move virtualization: load a SIMD constant vector
# from .rodata (movups xmm0, [rip+cvec]), store it to a .data global, reload it,
# and truncate the low lane. The VM must reach the constant and global via a
# bytecode-base-relative offset and move the full 128 bits. Net exit code 42.
_start:
    movups xmm0, xmmword ptr [rip + cvec]
    movups xmmword ptr [rip + gout], xmm0
    movups xmm1, xmmword ptr [rip + gout]
    cvttsd2si rdi, xmm1
    mov rax, 0x3c
    syscall
.section .rodata
cvec: .double 42.0
      .double 99.0
.data
gout: .quad 0
      .quad 0
