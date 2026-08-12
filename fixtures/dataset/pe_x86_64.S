.global _start
.text
_start:
    xor %ecx, %ecx
    mov $60, %eax
    syscall
