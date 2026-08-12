.intel_syntax noprefix
.global _start
.section .rodata
c22:
    .double 22.0
.data
slot:
    .quad 0
.text
# Engine-path rip-relative scalar-FP arithmetic: the function has a call (region
# rejects -> engine fallback). The run materializes 20.0 on the stack, loads it,
# then adds a .rodata double constant straight from the constant pool
# (addsd xmm0, [rip+c22]) - the compiler's usual form for a float literal -
# exercising the engine's rip-relative FP arithmetic handler. The result 42.0 is
# stored and its IEEE high byte read out: (bits >> 48) & 0xff == 0x45 == 69;
# sub/mul/div would differ.
#
# Built with .text as the highest-vaddr loadable segment so the large engine
# interpreter blob can be appended past it (see elf_vm_fpenginerip). Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static \
#     -Wl,--section-start=.rodata=0x401000 -Wl,--section-start=.data=0x402000 \
#     -Wl,-Ttext=0x500000 -o elf_vm_fpenginearithrip_x86_64 elf_vm_fpenginearithrip_x86_64.S
_start:
    movabs rax, 0x4034000000000000
    mov [rsp - 8], rax
    movsd xmm0, qword ptr [rsp - 8]
    addsd xmm0, qword ptr [rip + c22]
    movsd qword ptr [rsp - 16], xmm0
    mov rax, qword ptr [rsp - 16]
    shr rax, 48
    and rax, 0xff
    mov rdi, rax
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
