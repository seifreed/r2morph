.intel_syntax noprefix
.global _start
.text
# Engine-path scaled-index scalar-FP arithmetic (array accumulation): the function
# has a call (region rejects -> engine fallback). The run builds a two-element
# double array on the stack, loads a[0], then adds a[1] straight from the array
# via addsd xmm0, [rsp+rcx*8-16] (the sum += a[i] form) - exercising the engine's
# scaled-index FP arithmetic handler. The result 42.0 is stored and its IEEE high
# byte read out: (bits >> 48) & 0xff == 0x45 == 69; sub/mul/div differ.
_start:
    movabs rax, 0x4034000000000000
    mov [rsp - 16], rax
    movabs rax, 0x4036000000000000
    mov [rsp - 8], rax
    xor rcx, rcx
    movsd xmm0, qword ptr [rsp + rcx*8 - 16]
    mov rcx, 1
    addsd xmm0, qword ptr [rsp + rcx*8 - 16]
    movsd qword ptr [rsp - 24], xmm0
    mov rax, qword ptr [rsp - 24]
    shr rax, 48
    and rax, 0xff
    mov rdi, rax
    call helper
    mov rax, 0x3c
    syscall
helper:
    ret
