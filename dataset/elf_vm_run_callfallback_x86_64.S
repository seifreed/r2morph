.intel_syntax noprefix
.global _start
.text
# A function the whole-function control-flow VM rejects (it contains a call),
# but which holds a straight-line 64-bit register run. Exercises the
# fallback straight-line virtualization path (a single run -> VM trampoline)
# that the control-flow region path never reaches. Net exit code 45.
_start:
    mov rdi, 30
    add rdi, 20
    sub rdi, 5
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
