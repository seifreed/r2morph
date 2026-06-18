.intel_syntax noprefix
.global _start
.text
# Each flag-setting op here is flag-LIVE (a conditional branch reads its flags),
# so the region routes it to the synthesizing handler (opsynth): the result is
# computed by MBA and CF/OF/SF/ZF/PF are synthesized by hand. The branches check
# the trickiest flags - the sub borrow (CF) and signed overflow (OF) - so a wrong
# synthesis diverts to a non-42 exit. Net exit code 42 only if every checked flag
# matches the real CPU.
_start:
    mov  rdi, 5
    sub  rdi, 10            # 5 - 10 borrows: CF (borrow) must be set
    jnc  fail1
    movabs rdi, 0x8000000000000000
    sub  rdi, 1             # INT64_MIN - 1 overflows: OF must be set
    jno  fail2
    mov  rdi, 3
    add  rdi, 4             # 3 + 4 = 7, no carry: CF must be clear
    jc   fail3
    mov  rdi, 42
    jmp  done
fail1:
    mov  rdi, 1
    jmp  done
fail2:
    mov  rdi, 2
    jmp  done
fail3:
    mov  rdi, 4
done:
    mov  rax, 0x3c
    syscall
