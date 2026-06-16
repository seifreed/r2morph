# Jump-chain block-reordering fixture for r2morph.
#
# Every basic block ends in an unconditional control transfer, so the blocks
# can be physically permuted without inserting any new jumps (size-neutral).
# The control order entry -> b1 -> b2 -> b3 computes edi = 30 - 10 - 20 = 0,
# i.e. exit(0), and that result must hold regardless of the blocks' physical
# layout. Exercises BlockReorderingPass's relocation engine
# (block_reordering_relocation): blocks are relocated as whole units and every
# jmp is re-encoded for its new address.
.intel_syntax noprefix
.global _start
.text
_start:
    mov edi, 30
    jmp b1
b2:
    sub edi, 20
    jmp b3
b1:
    sub edi, 10
    jmp b2
b3:
    mov eax, 60
    syscall
