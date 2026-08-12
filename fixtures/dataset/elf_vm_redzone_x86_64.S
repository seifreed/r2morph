.intel_syntax noprefix
.global _start
.text
# Build:
#   clang --target=x86_64-linux-gnu -nostdlib -static -fuse-ld=lld \
#     -Wl,-e,_start -Wl,--build-id=none -o elf_vm_redzone_x86_64 \
#     elf_vm_redzone_x86_64.S
#
# Keep a live value at the bottom of the System V red zone while the callee runs
# arithmetic that the region VM lowers through its private operand stack.
_start:
    call redzone_value
    mov edi, eax
    mov eax, 60
    syscall

.type redzone_value,@function
redzone_value:
    mov eax, 42
    mov qword ptr [rsp-120], rax
    mov ecx, 7
    add ecx, 5
    sub ecx, 12
    mov eax, dword ptr [rsp-120]
    ret
.size redzone_value, .-redzone_value
