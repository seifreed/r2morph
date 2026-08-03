.intel_syntax noprefix
.global _start
.text
# A self-recursive function whose recursive call targets its own entry - an
# in-function call. Region extraction resolves that call target to item 0 and
# lowers it to a vcall that pushes a resume vIP and re-enters the VM at the entry;
# each ret becomes a return-aware vret. The whole recursion runs inside the VM.
# recurse(9) accumulates 9+8+...+1+0 = 45, which proves the recursive call pushed a
# resume vIP, re-entered the VM at the virtualized entry, and each vret resumed the
# correct caller frame (a wrong return discipline would corrupt the accumulation or
# trap). recurse is placed before _start so the entry function stays a plain
# out-of-function call into it.
recurse:
    cmp  rdi, 0
    jne  .Lstep
    xor  rax, rax
    ret
.Lstep:
    push rdi
    dec  rdi
    call recurse
    pop  rdi
    add  rax, rdi
    ret
_start:
    mov  rdi, 9
    call recurse
    mov  rdi, rax
    mov  rax, 0x3c
    syscall
