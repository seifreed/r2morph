.intel_syntax noprefix
.global _start
.text
# The shift's carry flag IS read by jc, so lowering shl to the vshift micro-op must
# still capture the real flags: edi=0x80000000, shl by 1 shifts bit 31 out -> CF=1
# -> jc taken -> exit 42. A vshift that dropped or mis-timed the flag capture would
# fall through to 99.
_start:
    mov edi, 0x80000000
    shl edi, 1
    jc carry
    mov edi, 99
    jmp done
carry:
    mov edi, 42
done:
    mov eax, 0x3c
    syscall
