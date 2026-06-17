.intel_syntax noprefix
.global _start
.text
# A real prologue/epilogue in the entry function (so r2 lists it and the region
# path virtualizes it): push rbp; mov rbp,rsp; sub rsp,N; a local via [rbp-8];
# add rsp,N; pop rbp. It exits through syscall instead of ret. A frame bug
# (relocation, rsp arithmetic, or frame-pointer copy) changes the exit code.
_start:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov rax, 0x2a
    mov qword ptr [rbp-8], rax
    mov rax, qword ptr [rbp-8]
    add rsp, 0x10
    pop rbp
    mov edi, eax
    mov eax, 0x3c
    syscall
