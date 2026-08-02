.intel_syntax noprefix
.global _start
.section .rodata
# Handler dispatch table: one 8-byte code pointer per opcode, followed by a
# null terminator so table-validation stops cleanly after the live entries.
handler_table:
    .quad h_loadi
    .quad h_addi
    .quad h_subi
    .quad h_halt
    .quad 0
# Bytecode program executed by the interpreter below. Opcode stream:
#   LOADI 30 ; ADDI 20 ; SUBI 5 ; HALT  ->  virtual accumulator = 45.
bytecode:
    .byte 0, 30
    .byte 1, 20
    .byte 2, 5
    .byte 3
.text
# A minimal, generic bytecode interpreter shaped like a code-virtualization VM:
# a computed-goto dispatch loop that fetches an opcode, indexes an encrypted-
# style handler table, and jumps through it (the defining register-indirect
# dispatch jmp). Each handler mutates a virtual accumulator (r12) held in a
# register file and jumps back to the dispatcher. This is the devirtualization
# oracle fixture: recovering it must yield the handler table, the bytecode
# region, and the VM context (vpc/accumulator registers). Exit code 45.
#
# Linked at a low, zero-based image so the absolute handler-table pointers and
# the dispatch jmp's absolute displacement match the loader's segment vaddrs
# exactly (a jump table bakes in absolute addresses; a 0x400000-based link would
# leave those operands pointing outside the analysis map). Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static \
#     -Wl,--image-base=0 -Wl,-Ttext=0x1000 \
#     -o elf_vm_interp_x86_64 elf_vm_interp_x86_64.S
_start:
    lea rbx, [rip + bytecode]       # rbx = virtual program counter (vpc)
    xor r12, r12                    # r12 = virtual accumulator
dispatch:
    movzx eax, byte ptr [rbx]       # fetch opcode
    inc rbx
    jmp qword ptr [handler_table + rax*8]   # computed-goto through the table
h_loadi:
    movzx r12d, byte ptr [rbx]      # accumulator = imm
    inc rbx
    jmp dispatch
h_addi:
    movzx ecx, byte ptr [rbx]       # accumulator += imm
    inc rbx
    add r12, rcx
    jmp dispatch
h_subi:
    movzx ecx, byte ptr [rbx]       # accumulator -= imm
    inc rbx
    sub r12, rcx
    jmp dispatch
h_halt:
    mov rdi, r12                    # exit(accumulator)
    mov rax, 0x3c
    syscall
