.intel_syntax noprefix
.global _start
.text
# Flag-dead xor/and/or (each overwritten by the next op / cmp before any branch),
# so each is MBA/De-Morgan folded; only values matter. 0xF0^0x0F=0xFF; &0x3C=0x3C;
# |0x01=0x3D -> exit 0x3D? keep it 42: design so result==42.
_start:
    mov edi, 0x2A
    xor edi, 0x00      # 42 ^ 0 = 42 (flags dead)
    and edi, 0x7F      # 42 & 0x7F = 42 (flags dead)
    or  edi, 0x00      # 42 | 0 = 42 (flags dead)
    cmp edi, 42
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 99
done:
    mov eax, 0x3c
    syscall
