.intel_syntax noprefix
.global _start
.type _start, @function
.type protected_body, @function
.text

_start:
    call protected_body
    mov edi, eax
    mov eax, 60
    syscall
.size _start, .-_start

protected_body:
    .cfi_startproc
    push rbp
    .cfi_def_cfa_offset 16
    .cfi_offset rbp, -16
    mov rbp, rsp
    .cfi_def_cfa_register rbp
    mov eax, 42
    pop rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
.size protected_body, .-protected_body
