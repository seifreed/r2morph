.intel_syntax noprefix
.global _start
.text
# Scalar-FP load/store virtualization: seed a stack-red-zone slot, move it into
# an xmm register and back out via movsd, then read the moved bits as an integer.
# movsd is a verbatim 64-bit move here, so the seeded low byte (0x2a) survives the
# round trip through the xmm save slot -> exit 42. Corrupting the FP load or store
# changes the exit code, so this fixture discriminates the handler's correctness.
_start:
    mov rax, 42
    mov [rsp - 8], rax
    movsd xmm3, qword ptr [rsp - 8]
    movsd qword ptr [rsp - 16], xmm3
    mov rdi, [rsp - 16]
    and rdi, 0xff
    mov rax, 0x3c
    syscall
