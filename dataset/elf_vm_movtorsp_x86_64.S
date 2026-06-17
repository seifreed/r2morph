.intel_syntax noprefix
.global _start
.text
# Frame teardown via explicit `mov rsp, rbp; pop rbp` (the clang epilogue). Same
# frame contract as the leave fixture; exercises the movtorsp handler and the
# frame-pointer snapshot in the balance guard (42 vs 99).
_start:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov rax, 0x2a
    mov qword ptr [rbp-8], rax
    mov rax, qword ptr [rbp-8]
    mov rsp, rbp
    pop rbp
    mov edi, eax
    mov eax, 0x3c
    syscall
