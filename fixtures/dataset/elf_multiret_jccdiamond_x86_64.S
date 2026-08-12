# A plain multi-block function with TWO independent returns reached by a jcc
# diamond and NO shared epilogue: each branch ends in its own ret. This is the
# multi-ret region shape (a region with more than one exit block, each an
# independent ret) rather than the usual single-epilogue diamond.
#
# classify is placed before _start so the call is a backward edge: r2 then bounds
# entry0 to _start alone and analyzes classify as its own function.
#
# Build: /opt/homebrew/opt/llvm/bin/clang --target=x86_64-linux-gnu -nostdlib \
#          -static -o elf_multiret_jccdiamond_x86_64 elf_multiret_jccdiamond_x86_64.S
#
# _start calls classify(5); 5 > 10 is false so jg is not taken -> rax = 17.
# Exit code 17.
.intel_syntax noprefix
.global _start
.global classify
.text
classify:
    cmp  rdi, 10
    jg   .Lbig
    mov  rax, 17
    ret
.Lbig:
    mov  rax, 99
    ret
_start:
    push rbp
    mov  rbp, rsp
    mov  rdi, 5
    call classify
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall
