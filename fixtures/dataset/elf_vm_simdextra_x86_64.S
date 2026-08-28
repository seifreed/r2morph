.intel_syntax noprefix
.global _start
.text

_start:
    lea rbx, [rip + vectors]
    movups xmm0, xmmword ptr [rbx]
    movups xmm1, xmmword ptr [rbx + 16]
    paddusb xmm0, xmm1
    psubusb xmm0, xmm1
    paddusw xmm0, xmm1
    psubusw xmm0, xmm1
    pavgb xmm0, xmm1
    pavgw xmm0, xmm1
    psadbw xmm0, xmm1
    pmaddwd xmm0, xmm1
    pmulhuw xmm0, xmm1
    pmulhw xmm0, xmm1
    packuswb xmm0, xmm1
    packssdw xmm0, xmm1
    punpcklbw xmm0, xmm1
    punpcklwd xmm0, xmm1
    movd edi, xmm0
    and edi, 0x7f
    mov eax, 60
    syscall

.section .rodata
.balign 16
vectors:
    .long 0x01020304, 0x11121314, 0x21222324, 0x31323334
    .long 0x04030201, 0x14131211, 0x24232221, 0x34333231
