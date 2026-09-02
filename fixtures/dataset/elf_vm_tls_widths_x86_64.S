.intel_syntax noprefix
.global _start
.text
_start:
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    mov byte ptr [rax], 0xa5
    mov word ptr [rax + 2], 0x1234
    mov rsi, rax
    mov edi, 0x1002
    mov eax, 158
    syscall
    call tls_widths
    mov edi, eax
    mov eax, 60
    syscall

.type tls_widths, @function
tls_widths:
    mov al, byte ptr fs:[0]
    mov byte ptr fs:[1], al
    mov cx, word ptr fs:[2]
    mov word ptr fs:[4], cx
    movzx edi, al
    cmp edi, 0xa5
    jne bad
    movzx edi, cx
    cmp edi, 0x1234
    jne bad
    mov eax, 42
    ret
bad:
    mov eax, 99
    ret
.size tls_widths, .-tls_widths
