.intel_syntax noprefix
.global _start
.text
# Exercises rip-relative memory micro-op lowering end to end: a global load
# (riprel_load), a rip-relative subtract (opriprel) whose borrow flag drives a
# branch, a global store (riprel_store), a rip-relative read-modify-write
# (opmemdstrip), and a reload. Correct execution exits 42; a wrongly synthesized
# borrow flag on the opriprel subtract exits 99.
_start:
    mov rax, qword ptr [rip + gA]      # riprel_load:  rax = 50
    sub rax, qword ptr [rip + gB]      # opriprel:     rax = 42, no borrow (50 > 8)
    jc  fail                            # borrow wrongly captured -> fail
    mov qword ptr [rip + gR], rax      # riprel_store: gR = 42
    mov rcx, qword ptr [rip + gZ]      # riprel_load:  rcx = 0
    add qword ptr [rip + gR], rcx      # opmemdstrip:  gR += 0 (still 42)
    mov rdi, qword ptr [rip + gR]      # riprel_load:  rdi = 42
    mov rax, 0x3c
    syscall
fail:
    mov rdi, 99
    mov rax, 0x3c
    syscall
.data
gA: .quad 50
gB: .quad 8
gZ: .quad 0
gR: .quad 0
