.intel_syntax noprefix
.global _start
.text
# Engine-path reg-reg GP arithmetic (add/sub/xor/and/or) that micro-op splitting
# lowers to a virtual-stack push/binop/pop sequence per native op. A call forces
# engine fallback (the region VM rejects calls). The run nets exit code 42; if the
# micro-op lowering were wrong the exit code would differ.
_start:
    mov rdi, 40
    mov rsi, 10
    add rdi, rsi     # 50   (reg-reg add)
    mov rsi, 8
    sub rdi, rsi     # 42   (reg-reg sub; order-sensitive)
    mov rsi, 0
    xor rdi, rsi     # 42   (reg-reg xor with 0)
    mov rsi, -1
    and rdi, rsi     # 42   (reg-reg and with all-ones)
    mov rsi, 0
    or  rdi, rsi     # 42   (reg-reg or with 0)
    call helper
    xor rsi, rsi
    mov rax, 0x3c
    syscall
helper:
    ret
