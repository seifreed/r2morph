.intel_syntax noprefix
.global _start
.text
# Engine-path immediate-count shifts: the function has a call, so the
# whole-function control-flow VM rejects it and the engine virtualizes the
# straight-line run before the call. That run uses shl/sar/shr (64-bit) plus a
# 32-bit shl, netting exit code 42 in rdi. Flags are dead at the call boundary,
# so the run is virtualizable under the engine's flags-dead precondition. If the
# shifts were left native the exit would still be 42, so the test also asserts the
# shifts lower to VM ops (a decode check) to rule out a false green.
_start:
    mov rdi, 10
    shl rdi, 3       # 80   (shl, 64-bit)
    sar rdi, 1       # 40   (sar, 64-bit, arithmetic)
    mov rsi, 8
    shr rsi, 2       # 2    (shr, 64-bit)
    add rdi, rsi     # 42
    mov ecx, 21
    shl ecx, 1       # 42   (shl, 32-bit; result dead, reaches the width-32 path)
    call helper
    xor rsi, rsi
    mov rax, 0x3c
    syscall
helper:
    ret
