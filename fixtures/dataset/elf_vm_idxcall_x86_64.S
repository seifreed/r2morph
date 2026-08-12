.intel_syntax noprefix
.global _start
.global twice
.text
# Callee before the entry so r2 keeps it a distinct function; reached only
# through the function-pointer table below.
twice:
    lea  rax, [rdi + rdi]
    ret
.data
# A function-pointer table - the array-of-vtables / switch-via-pointer-table
# dispatch shape. Index 1 selects the callee.
tbl:
    .quad 0
    .quad twice
.text
# Region-reducible except for one indexed memory-indirect call
# (call qword [tbl + rcx*8]). The VM must compute base+index*scale, load the
# callee from the table, bridge out with the argument and capture the result.
# Net exit code 42 (= twice(21)).
_start:
    push rbp
    mov  rbp, rsp
    lea  rax, [rip + tbl]
    mov  rcx, 1
    mov  rdi, 21
    call qword ptr [rax + rcx*8]
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall
