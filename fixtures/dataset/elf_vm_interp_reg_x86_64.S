.intel_syntax noprefix
.global _start
.section .rodata
# Handler dispatch table: one 8-byte code pointer per opcode.
handler_table:
    .quad h_loadi
    .quad h_addi
    .quad h_subi
    .quad h_halt
    .quad 0
bytecode:
    .byte 0, 30
    .byte 1, 20
    .byte 2, 5
    .byte 3
.text
# Same generic bytecode interpreter as elf_vm_interp, but with the classic
# two-instruction register-indirect dispatch: load the handler address from the
# table into a register, then jump through the register. This is the form the
# region virtualizer lowers to a plain indexed load plus an ijmp (register-indirect
# computed jump), so no memory-indexed jump handler is needed to virtualize it.
# Exit code 45.
#
# Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static \
#     -Wl,--image-base=0 -Wl,-Ttext=0x1000 \
#     -o elf_vm_interp_reg_x86_64 elf_vm_interp_reg_x86_64.S
_start:
    lea rbx, [rip + bytecode]       # rbx = virtual program counter (vpc)
    xor r12, r12                    # r12 = virtual accumulator
    lea rbp, [rip + handler_table]  # rbp = handler table base
dispatch:
    movzx eax, byte ptr [rbx]       # fetch opcode
    inc rbx
    shl rax, 3                      # opcode * 8 (pointer-sized table stride)
    add rax, rbp                    # &handler_table[opcode]
    mov rdx, qword ptr [rax]        # load handler address from the table
    jmp rdx                         # register-indirect computed goto
h_loadi:
    movzx r12d, byte ptr [rbx]
    inc rbx
    jmp dispatch
h_addi:
    movzx ecx, byte ptr [rbx]
    inc rbx
    add r12, rcx
    jmp dispatch
h_subi:
    movzx ecx, byte ptr [rbx]
    inc rbx
    sub r12, rcx
    jmp dispatch
h_halt:
    mov rdi, r12
    mov rax, 0x3c
    syscall
