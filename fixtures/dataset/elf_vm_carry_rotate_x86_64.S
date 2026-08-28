.intel_syntax noprefix
.global _start
.text
# RCL consumes the incoming virtual CF and RCR must preserve the same contract
# when its count comes from CL. Both branches also verify the native result.
_start:
    mov eax, 0x80000000
    mov edx, 0
    cmp edx, 1
    rcl eax, 1
    jc rcl_carry
    mov edi, 99
    jmp done
rcl_carry:
    mov edx, 1
    cmp eax, edx
    jne bad

    mov eax, 1
    mov ecx, 1
    cmp ecx, 2
    rcr eax, cl
    jc rcr_carry
    mov edi, 98
    jmp done
rcr_carry:
    mov edx, 0x80000000
    cmp eax, edx
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 97
done:
    mov eax, 60
    syscall
