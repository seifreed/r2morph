.intel_syntax noprefix
.global _start
.text
# Engine-path immediate-form GP arithmetic (add/sub/xor/and/or dst, imm) that
# micro-op splitting lowers to vpush_slot/vpush_imm/vbinop/vpop over the vstack. A
# call forces engine fallback. Nets exit 42; a wrong immediate lowering - notably
# the order-sensitive imm sub - would change the exit code.
_start:
    mov rdi, 100
    add rdi, 5       # 105  (imm add)
    sub rdi, 63      # 42   (imm sub, order-sensitive: dst - imm)
    xor rdi, 0       # 42   (imm xor)
    and rdi, 0xff    # 42   (imm and)
    or  rdi, 0       # 42   (imm or)
    call helper
    xor rsi, rsi
    mov rax, 0x3c
    syscall
helper:
    ret
