.intel_syntax noprefix
.global _start
.text
# Establish a real per-thread GS base before reading a TLS word. The setup
# syscalls remain native; the following GS-relative load is VM-lowerable.
_start:
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    mov qword ptr [rax], 46
    mov rsi, rax
    mov edi, 0x1001
    mov eax, 158
    syscall
    mov rax, qword ptr gs:[0]
    mov edi, eax
    mov eax, 60
    syscall
