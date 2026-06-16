# Two adjacent equal-size basic blocks ("mov eax,N; jmp done" = 7 bytes each),
# both ending in a RELATIVE jmp. Block reordering's byte-swap would relocate them
# without re-encoding the jmp offsets, sending control flow to the wrong address.
.intel_syntax noprefix
.global _start
.text
_start:
    cmp edi, 0
    je equal
    mov eax, 1          # block A: 7 bytes (b8 imm32 + eb rel8)
    jmp done
equal:
    mov eax, 2          # block B: 7 bytes
    jmp done
done:
    mov edi, eax        # exit code = eax (1 or 2); should be 2 (edi starts 0 -> je taken)
    mov eax, 60
    syscall
