# A 4-case switch built with an ABSOLUTE jump table (non-PIE). The computed jump
#   jmp qword ptr [.Ltab + rdi*8]
# reads a full 64-bit case-target pointer from a .rodata .quad table indexed by
# rdi. r2 recognises this as a switch and attaches a switch_op with the 4 case
# targets to the computed-jump block.
#
# CRITICAL build note: a plain -static build without a consistent image base
# mislinks the absolute table pointer OUTSIDE r2's memory maps, so r2 cannot
# resolve the table. Linking with -fno-pic and --image-base=0 keeps the table
# pointer mapped so r2 resolves the switch. Verified empirically.
#
# Build: /opt/homebrew/opt/llvm/bin/clang --target=x86_64-linux-gnu -nostdlib \
#          -static -fno-pic -Wl,--image-base=0 \
#          -o elf_switch_abs_x86_64 elf_switch_abs_x86_64.S
#
# _start calls dispatch(2); case 2 -> rax = 30. Exit code 30.
.intel_syntax noprefix
.global _start
.global dispatch
.text
dispatch:
    cmp  rdi, 3
    ja   .Ldef
    jmp  qword ptr [.Ltab + rdi*8]
.Lc0:
    mov  rax, 10
    jmp  .Lend
.Lc1:
    mov  rax, 20
    jmp  .Lend
.Lc2:
    mov  rax, 30
    jmp  .Lend
.Lc3:
    mov  rax, 40
    jmp  .Lend
.Ldef:
    mov  rax, 99
    jmp  .Lend
.Lend:
    ret
_start:
    push rbp
    mov  rbp, rsp
    mov  rdi, 2
    call dispatch
    mov  rdi, rax
    pop  rbp
    mov  rax, 0x3c
    syscall

.section .rodata
.align 8
.Ltab:
    .quad .Lc0
    .quad .Lc1
    .quad .Lc2
    .quad .Lc3
