.intel_syntax noprefix
.global _start
.text
# Frame teardown via `leave` (mov rsp,rbp; pop rbp), the gcc -O0 epilogue. The
# entry sets up a frame, stores/loads a local via [rbp-8], then `leave` restores
# rsp and rbp before the syscall exit. A frame-snapshot or pop bug changes the
# exit code (42 vs 99).
_start:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov rax, 0x2a
    mov qword ptr [rbp-8], rax
    mov rax, qword ptr [rbp-8]
    leave
    mov edi, eax
    mov eax, 0x3c
    syscall
