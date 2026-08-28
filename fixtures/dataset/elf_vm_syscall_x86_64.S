.intel_syntax noprefix
.global _start
.text
# Returning syscall bridge: mmap returns a pointer used by following virtualized
# memory operations. The final exit syscall remains a native VM exit.
_start:
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    mov qword ptr [rax], 47
    mov rdi, qword ptr [rax]
    mov eax, 60
    syscall
