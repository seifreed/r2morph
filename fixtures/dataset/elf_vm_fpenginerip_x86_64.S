.intel_syntax noprefix
.global _start
.section .rodata
fortytwo:
    .double 42.0
.data
slot:
    .quad 0
.text
# Engine-path rip-relative scalar-FP load/store: the function has a call (region
# rejects -> engine fallback). The run loads a .rodata double constant via
# movsd [rip+fortytwo], stores it to a .data global via movsd [rip+slot], reloads
# it, and truncates to an int - exercising the engine's rip-relative FP load/store
# handlers (the dominant FP memory form: constants live in .rodata). Exit 42.
#
# Built with .text placed ABOVE .rodata/.data so it is the highest-vaddr
# loadable segment - the engine interpreter blob (tens of KB) is appended past
# .text and must not overlap a trailing loadable segment, or the injector
# refuses (the region VM's blob is small enough to fit a normal layout; the
# engine's is not). Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static \
#     -Wl,--section-start=.rodata=0x401000 -Wl,--section-start=.data=0x402000 \
#     -Wl,-Ttext=0x500000 -o elf_vm_fpenginerip_x86_64 elf_vm_fpenginerip_x86_64.S
_start:
    movsd xmm0, qword ptr [rip + fortytwo]
    movsd qword ptr [rip + slot], xmm0
    movsd xmm1, qword ptr [rip + slot]
    cvttsd2si rdi, xmm1
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
