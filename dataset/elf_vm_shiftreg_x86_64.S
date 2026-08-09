.intel_syntax noprefix
.global _start
.text
# Variable-count (cl) shifts/rotates virtualized. shl 1<<4=16; shr 0x80>>7=1;
# rol 1 by 3 = 8; and a cl=0 shift must leave flags unchanged (ZF set before it
# survives, jnz not taken - the handler merges the program flags for the zero-count
# case). Exit 42 needs every value and the zero-count flag behaviour correct.
_start:
    mov eax, 1
    mov ecx, 4
    shl eax, cl
    cmp eax, 16
    jne fail
    mov edx, 0x80
    mov ecx, 7
    shr edx, cl
    cmp edx, 1
    jne fail
    mov ebx, 1
    mov ecx, 3
    rol ebx, cl
    cmp ebx, 8
    jne fail
    xor esi, esi
    mov ebp, 5
    xor ecx, ecx
    shl ebp, cl
    jnz fail
    mov edi, 42
    jmp done
fail:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
