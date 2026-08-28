.intel_syntax noprefix
.global _start
.text
# Establish a real per-thread FS base before reading a TLS word. The first
# system calls remain native; the following FS-relative load is VM-lowerable.
_start:
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    mov rsi, rax
    mov edi, 0x1002
    mov eax, 158
    syscall
    mov rax, qword ptr fs:[0]
    mov edi, 45
    mov eax, 60
    syscall
