.text
# The helper is reached through a constant indirect call so the caller remains
# the only analyzed function. It leaves two vector arguments in XMM registers.
set_vectors:
    movabsq $0x4034000000000000, %rax
    movq %rax, %xmm0
    movabsq $0x4036000000000000, %rax
    movq %rax, %xmm1
    ret

# The callee models the SysV variadic vector contract: AL carries the number
# of vector arguments and xmm0/xmm1 carry two doubles. It returns 69 only when
# both vector values and the count are preserved across virtualization.
sum_variadic:
    cmpb $2, %al
    jne .Lbad_al
    movq %xmm0, %rax
    movabsq $0x4034000000000000, %rdx
    cmpq %rdx, %rax
    jne .Lbad_vector
    movq %xmm1, %rax
    movabsq $0x4036000000000000, %rdx
    cmpq %rdx, %rax
    jne .Lbad_vector
    movl $69, %eax
    ret

.Lbad_al:
    movl $2, %eax
    ret

.Lbad_vector:
    movl $3, %eax
    ret

.globl _start
_start:
    movabsq $set_vectors, %rax
    call *%rax
    movabsq $sum_variadic, %r11
    movl $2, %eax
    call *%r11
    movl %eax, %edi
    movl $60, %eax
    syscall
