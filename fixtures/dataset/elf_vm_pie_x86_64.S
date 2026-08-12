# A plain arithmetic function built as a position-independent executable (PIE,
# ET_DYN). No switch, no computed jump: a single straight-line whole-function
# region (mov/add/imul/sub plus a rip-relative .rodata load) that the region VM
# can virtualize in one go. Every reference is rip-relative, so the image runs
# correctly at any load base - which is exactly what makes it a probe for
# injection into an ET_DYN image: a trampoline or interpreter that baked in a
# link-time absolute address would diverge as soon as the image is biased.
#
# Build (static-PIE so -nostdlib links without a dynamic loader, still ET_DYN):
#   /opt/homebrew/opt/llvm/bin/clang --target=x86_64-linux-gnu -nostdlib \
#     -fpic -static-pie -o elf_vm_pie_x86_64 elf_vm_pie_x86_64.S
#
# _start calls compute(7, 5, 4) = (7 + 5) * 6 - 4 + 5 = 73. Exit code 73.
.intel_syntax noprefix
.global _start
.global compute
.text
compute:
    mov    rax, rdi
    add    rax, rsi
    imul   rax, rax, 6
    sub    rax, rdx
    mov    rcx, qword ptr [rip + .Lbump]
    add    rax, rcx
    ret
_start:
    push   rbp
    mov    rbp, rsp
    mov    rdi, 7
    mov    rsi, 5
    mov    rdx, 4
    call   compute
    mov    rdi, rax
    pop    rbp
    mov    rax, 0x3c
    syscall

.section .rodata
.align 8
.Lbump:
    .quad 5
