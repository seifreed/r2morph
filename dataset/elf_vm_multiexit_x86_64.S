.intel_syntax noprefix
.global _start
.text
# Two distinct exit points (early-exit error path + main path).
_start:
    mov edi, 7
    cmp edi, 5
    jg big
    mov edi, 1
    mov eax, 0x3c
    syscall
big:
    mov edi, 42
    mov eax, 0x3c
    syscall
