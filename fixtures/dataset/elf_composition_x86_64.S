.intel_syntax noprefix
.global _start
.text

_start:
    mov edi, 1
    call run
    mov edi, eax
    mov eax, 60
    syscall

.type run,@function
run:
    push rbp
    mov rbp, rsp
    mov rax, rax
    mov r10, r10
    cmp edi, 0
    je .Lzero
    call branchy
    mov ebx, eax
    call stack_run
    add eax, ebx
    jmp .Ldone
.Lzero:
    call short_probe
.Ldone:
    pop rbp
    ret
.size run,.-run

.type branchy,@function
branchy:
    push rbp
    mov rbp,rsp
    mov rcx,rdi
    mov rax,rdi
    add rax,3
    mov rdx,rax
    add rax,4
    test edi,edi
    jz .Lbranch_zero
    mov rax, rax
    imul rax, rax, 2
    jmp .Lbranch_done
.Lbranch_zero:
    sub rax, 1
.Lbranch_done:
    pop rbp
    add eax, 1
    ret
.size branchy,.-branchy

.type short_probe,@function
short_probe:
    xor rcx,rcx
    jrcxz .Lshort_done
    .rept 8
    nop
    .endr
.Lshort_done:
    mov eax,7
    ret
.size short_probe,.-short_probe

.type straight,@function
straight:
    push rbp
    mov rbp,rsp
    nop
    mov eax,9
    add eax,1
    add eax,2
    pop rbp
    ret
.size straight,.-straight

.type nop_anchor,@function
nop_anchor:
    mov rax,rax
    mov r10,r10
    mov eax,0
    ret
.size nop_anchor,.-nop_anchor

.type stack_run,@function
stack_run:
    lea rdi, [rip + stack_message]
    call consume
    ret
.size stack_run,.-stack_run

.type consume,@function
consume:
    movzx eax, byte ptr [rdi]
    ret
.size consume,.-consume

.fill 0x4000, 1, 0x90

.section .rodata
stack_message:
    .asciz "composition-stack-message"
unused_message:
    .asciz "unreferenced-composition-message"
