# A 4-case switch built as a position-independent executable (PIE) using the
# rip-relative OFFSET-table idiom emitted by gcc/clang under -fpic:
#   lea    rax, [rip + .Ltab]              ; table base
#   movsxd rcx, dword ptr [rax + rdi*4]    ; signed 32-bit offset of the case
#   add    rcx, rax                        ; case target = base + offset
#   jmp    rcx
# The .rodata table holds 4 relative offsets (.long .Lcase - .Ltab) rather than
# absolute pointers, so the whole thing relocates with the image. r2 resolves the
# computed jump and attaches a switch_op / code xrefs for the case targets.
#
# Build (static-PIE so -nostdlib links without a dynamic loader, still ET_DYN):
#   /opt/homebrew/opt/llvm/bin/clang --target=x86_64-linux-gnu -nostdlib \
#     -fpic -static-pie -o elf_switch_pie_x86_64 elf_switch_pie_x86_64.S
#
# _start calls dispatch(2); case 2 -> rax = 30. Exit code 30.
.intel_syntax noprefix
.global _start
.global dispatch
.text
dispatch:
    cmp    rdi, 3
    ja     .Ldef
    lea    rax, [rip + .Ltab]
    movsxd rcx, dword ptr [rax + rdi*4]
    add    rcx, rax
    jmp    rcx
.Lc0:
    mov    rax, 10
    jmp    .Lend
.Lc1:
    mov    rax, 20
    jmp    .Lend
.Lc2:
    mov    rax, 30
    jmp    .Lend
.Lc3:
    mov    rax, 40
    jmp    .Lend
.Ldef:
    mov    rax, 99
    jmp    .Lend
.Lend:
    ret
_start:
    push   rbp
    mov    rbp, rsp
    mov    rdi, 2
    call   dispatch
    mov    rdi, rax
    pop    rbp
    mov    rax, 0x3c
    syscall

.section .rodata
.align 4
.Ltab:
    .long .Lc0 - .Ltab
    .long .Lc1 - .Ltab
    .long .Lc2 - .Ltab
    .long .Lc3 - .Ltab
