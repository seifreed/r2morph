.intel_syntax noprefix
.global _start
.section .rodata
# Handler dispatch table: one 8-byte code pointer per opcode.
handler_table:
    .quad h_loadi
    .quad h_addi
    .quad h_subi
    .quad h_check
    .quad h_halt
    .quad 0
bytecode:
    .byte 0, 30
    .byte 1, 20
    .byte 2, 5
    .byte 3
    .byte 4
.text
# A generic bytecode interpreter with the same register-indirect dispatch as
# elf_vm_interp_reg (load the handler address from the table, jump through the
# register). It adds a "check" opcode that preserves a condition flag across a
# flag-live scratch computation by bracketing it with pushfq/popfq - the classic
# flag-preservation idiom, the shape where flag state crosses the computed jump.
# The accumulator reaches 45 (30 + 20 - 5); the check verifies it and only leaves
# the accumulator intact if the preserved condition survives the bracket.
# Exit code 45.
#
# Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static \
#     -Wl,--image-base=0 -Wl,-Ttext=0x1000 \
#     -o elf_vm_interp_stack_x86_64 elf_vm_interp_stack_x86_64.S
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
h_check:
    mov rcx, r12
    sub rcx, 45                     # condition C: ZF = (accumulator == 45)
    pushfq                          # save C across the flag-live scratch op below
    mov r8, 2
    sub r8, 1                       # flag-live scratch (ZF = 0), read by jnz -> clobbers C
    jnz check_restore
    mov r12, 77                     # skipped on the real path (guards the branch)
check_restore:
    popfq                           # restore C
    jz check_ok                     # C held (accumulator was 45) -> keep it
    mov r12, 88                     # C lost -> force a wrong exit code
check_ok:
    jmp dispatch
h_halt:
    mov rdi, r12
    mov rax, 0x3c
    syscall
