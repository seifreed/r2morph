.intel_syntax noprefix
.global _start
.text
# Exercises virtualization of movabs (mov reg, imm64). Each 64-bit constant is
# shifted down to expose its high word and branched on, so a handler that
# dropped the upper 32 bits of the immediate would diverge; original and
# virtualized binaries must agree (exit 42, a truncated immediate would exit 99).
_start:
    mov rsi, 0x100000001        # movabs: high word must survive
    shr rsi, 32                 # rsi = 1
    cmp esi, 1
    jne bad
    mov rcx, 0xdeadbeef00       # movabs
    shr rcx, 8                  # rcx = 0xdeadbeef
    cmp ecx, 0xdeadbeef
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
