.intel_syntax noprefix
.global _start
.text

_start:
    sub rsp, 16
    mov rax, 0x8877665544332211
    mov qword ptr [rsp], rax

    mov rax, 0x1122334455667700
    mov al, byte ptr [rsp]
    mov rcx, 0x1122334455667711
    cmp rax, rcx
    jne .Lbad

    mov rax, 0x1122334455660000
    mov ax, word ptr [rsp]
    mov rcx, 0x1122334455662211
    cmp rax, rcx
    jne .Lbad

    mov rax, 0xAABBCCDDEEFF0099
    mov byte ptr [rsp+8], al
    mov word ptr [rsp+10], ax
    movzx eax, byte ptr [rsp+8]
    cmp eax, 0x99
    jne .Lbad
    movzx eax, word ptr [rsp+10]
    cmp eax, 0x0099
    jne .Lbad

    add rsp, 16
    mov edi, 80
    jmp .Lexit

.Lbad:
    add rsp, 16
    mov edi, 1

.Lexit:
    mov eax, 60
    syscall
