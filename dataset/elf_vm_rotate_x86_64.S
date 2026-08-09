.intel_syntax noprefix
.global _start
.text
# Rotates share the vshift micro-op but, unlike a shift, leave SF/ZF/AF/PF untouched
# and only define CF (and OF for count 1). The handler must therefore MERGE the
# program's incoming flags with the rotate's CF/OF, not overwrite them like a shift.
# This fixture discriminates both halves of that contract:
#   part 1 - xor sets ZF=1; rol must PRESERVE it, so jnz is NOT taken. A handler that
#            overwrote the flags with its count-decode would clear ZF and take jnz.
#   part 2 - ror of an odd value rotates the low bit into CF; jnc must NOT be taken. A
#            handler that dropped the real CF would fall through.
# Both must hold for exit 42; any rotate-flag error yields 99.
_start:
    xor esi, esi
    mov edi, 5
    rol edi, 3
    jnz fail
    mov edi, 1
    ror edi, 1
    jnc fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
