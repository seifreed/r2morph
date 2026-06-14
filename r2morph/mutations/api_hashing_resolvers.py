"""Pure API hashing resolver assembly generators."""

from __future__ import annotations


def generate_resolver_x64(hash_value: int, dll_name: str = "kernel32.dll") -> str:
    """
    Generate x64 assembly for PEB-based API resolution by hash.
    """
    asm = f"""
; API Hash Resolver - resolving hash 0x{hash_value:08X}
; Target: {dll_name}
; Uses GS:[0x60] to access PEB on x64

resolve_api_{hash_value:08X}:
    push rbx                    ; save non-volatile registers
    push rsi
    push rdi
    push r12
    push r13
    push r14

    mov rax, gs:[0x60]          ; PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rax, [rax + 0x20]       ; Ldr->InMemoryOrderModuleList
    mov rdx, [rax]              ; first entry (ntdll.dll)
    mov rdx, [rdx]              ; second entry (kernel32.dll usually)
    mov rsi, [rdx + 0x20]        ; base address

    ; Walk exports
    mov eax, [rsi + 0x3C]        ; e_lfanew (PE header offset)
    mov eax, [rsi + rax + 0x88]  ; Export table RVA
    add rax, rsi                 ; Export table address

    mov r12d, [rax + 0x18]       ; NumberOfNames
    mov r13d, [rax + 0x20]       ; AddressOfNames RVA
    mov r14d, [rax + 0x24]       ; AddressOfNameOrdinals RVA
    add r13, rsi                 ; AddressOfNames address
    add r14, rsi                 ; AddressOfNameOrdinals address

    xor ebx, ebx                 ; counter

.loop_{hash_value:08X}:
    mov edx, 0x{hash_value:08X}  ; target hash
    mov ecx, [r13 + rbx*4]       ; Name RVA
    add rcx, rsi                 ; Name address

    ; inline hash comparison
    xor edi, edi                 ; hash accumulator
    mov r8, rcx                  ; name pointer

.hash_loop_{hash_value:08X}:
    movzx eax, byte [r8]
    test al, al
    jz .hash_done_{hash_value:08X}
    ror edi, 13
    add edi, eax
    and edi, 0xFFFFFFFF
    inc r8
    jmp .hash_loop_{hash_value:08X}

.hash_done_{hash_value:08X}:
    cmp edi, edx
    je .found_{hash_value:08X}
    inc rbx
    cmp ebx, r12d
    jb .loop_{hash_value:08X}
    xor rax, rax                 ; not found, return 0
    jmp .done_{hash_value:08X}

.found_{hash_value:08X}:
    movzx eax, word [r14 + rbx*2]  ; ordinal
    mov ecx, [rax + 0x1C]          ; AddressOfFunctions RVA
    mov eax, [rcx + rax*4]         ; function RVA
    add rax, rsi                   ; function address

.done_{hash_value:08X}:
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
"""
    return asm


def generate_resolver_x86(hash_value: int, dll_name: str = "kernel32.dll") -> str:
    """
    Generate x86 (32-bit) assembly for PEB-based API resolution by hash.
    """
    asm = f"""
; API Hash Resolver (x86) - resolving hash 0x{hash_value:08X}
; Target: {dll_name}
; Uses FS:[0x30] to access PEB on x86

resolve_api_{hash_value:08X}:
    push ebx
    push esi
    push edi
    push ebp

    mov eax, fs:[0x30]           ; PEB
    mov eax, [eax + 0xC]         ; PEB->Ldr
    mov eax, [eax + 0x14]        ; Ldr->InMemoryOrderModuleList
    mov edx, [eax]               ; first entry
    mov edx, [edx]               ; second entry (kernel32.dll)
    mov esi, [edx + 0x10]        ; base address

    ; Walk exports
    mov eax, [esi + 0x3C]        ; e_lfanew
    mov eax, [esi + eax + 0x78]  ; Export table RVA
    add eax, esi                 ; Export table address

    mov ebp, [eax + 0x18]        ; NumberOfNames
    mov ebx, [eax + 0x20]        ; AddressOfNames RVA
    add ebx, esi                 ; AddressOfNames address
    mov ecx, [eax + 0x24]        ; AddressOfNameOrdinals RVA
    add ecx, esi                 ; AddressOfNameOrdinals address

    xor edx, edx                 ; counter

.loop_{hash_value:08X}:
    mov eax, 0x{hash_value:08X}  ; target hash
    push eax                     ; save target hash
    mov eax, [ebx + edx*4]       ; Name RVA
    add eax, esi                 ; Name address

    ; inline hash comparison
    xor edi, edi                 ; hash accumulator
    push eax                     ; save name pointer
    push edi                     ; save hash accumulator

    mov ebp, esp                 ; save stack frame pointer

.hash_loop_{hash_value:08X}:
    mov eax, [ebp + 4]           ; get name pointer from saved location
    movzx eax, byte [eax]        ; get char from name
    test al, al
    jz .hash_done_{hash_value:08X}
    ror edi, 13
    add edi, eax
    and edi, 0xFFFFFFFF
    inc dword [ebp + 4]         ; increment name pointer
    jmp .hash_loop_{hash_value:08X}

.hash_done_{hash_value:08X}:
    pop edi                      ; restore hash accumulator
    pop eax                      ; name pointer (discard)
    pop eax                      ; restore target hash
    cmp edi, eax
    je .found_{hash_value:08X}
    inc edx
    cmp edx, ebp
    jb .loop_{hash_value:08X}
    xor eax, eax                ; not found
    jmp .done_{hash_value:08X}

.found_{hash_value:08X}:
    movzx eax, word [ecx + edx*2]  ; ordinal
    mov edx, [esi + 0x3C]
    mov edx, [esi + edx + 0x78]    ; Export table RVA
    mov edx, [edx + 0x1C]          ; AddressOfFunctions RVA
    add edx, esi                   ; AddressOfFunctions address
    mov eax, [edx + eax*4]        ; function RVA
    add eax, esi                   ; function address

.done_{hash_value:08X}:
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret
"""
    return asm


def generate_resolve_function(arch: str = "x64") -> str:
    """
    Generate a single resolve function that takes hash as argument.
    """
    if arch == "x64":
        return """
; Generic API resolver - takes hash in RCX, returns address in RAX
resolve_api_hash:
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    mov r12, rcx                ; save target hash

    mov rax, gs:[0x60]          ; PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rax, [rax + 0x20]       ; InMemoryOrderModuleList

    ; Walk module list to find kernel32
.find_kernel32:
    mov rdx, [rax]              ; next entry
    mov rsi, [rdx + 0x20]        ; base address
    mov edi, [rsi + 0x3C]        ; e_lfanew
    mov edi, [rsi + rdi + 0x88]  ; Export RVA
    test edi, edi
    jz .next_module
    jmp .walk_exports

.next_module:
    mov rax, rdx
    jmp .find_kernel32

.walk_exports:
    add rdi, rsi                 ; Export table
    mov ebx, [rdi + 0x18]        ; NumberOfNames
    mov r13d, [rdi + 0x20]       ; AddressOfNames RVA
    add r13, rsi
    mov r11d, [rdi + 0x24]       ; AddressOfNameOrdinals RVA
    add r11, rsi

    xor edx, edx                 ; counter

.hash_loop:
    mov ecx, [r13 + rdx*4]       ; Name RVA
    add rcx, rsi                 ; Name address
    xor eax, eax                 ; hash accumulator

.name_loop:
    movzx ebx, byte [rcx]
    test bl, bl
    jz .compare_hash
    ror eax, 13
    add eax, ebx
    and eax, 0xFFFFFFFF
    inc rcx
    jmp .name_loop

.compare_hash:
    cmp eax, r12d
    je .found

    inc edx
    mov ebx, [rdi + 0x18]
    cmp edx, ebx
    jb .hash_loop

    xor rax, rax                 ; not found
    jmp .done

.found:
    movzx eax, word [r11 + rdx*2]
    mov ecx, [rdi + 0x1C]        ; AddressOfFunctions RVA
    add ecx, rsi
    mov eax, [ecx + eax*4]       ; function RVA
    add rax, rsi                 ; function address

.done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
"""
    return """
; Generic API resolver (x86) - takes hash on stack, returns address in EAX
resolve_api_hash:
    push ebx
    push esi
    push edi
    push ebp

    mov ebp, [esp + 0x14]        ; target hash from stack

    mov eax, fs:[0x30]           ; PEB
    mov eax, [eax + 0xC]         ; PEB->Ldr
    mov eax, [eax + 0x14]        ; InMemoryOrderModuleList

    ; Find kernel32.dll
.find_kernel32:
    mov edx, [eax]
    mov esi, [edx + 0x10]        ; base address

.walk_exports:
    mov eax, [esi + 0x3C]        ; e_lfanew
    mov eax, [esi + eax + 0x78]  ; Export RVA
    add eax, esi

    mov ebx, [eax + 0x18]        ; NumberOfNames
    mov ecx, [eax + 0x20]        ; AddressOfNames
    add ecx, esi
    push ecx
    mov edx, [eax + 0x24]        ; AddressOfNameOrdinals
    add edx, esi

    xor ecx, ecx                 ; counter

.hash_loop:
    mov eax, [esp]
    mov eax, [eax + ecx*4]       ; Name RVA
    add eax, esi                 ; Name address
    push edx
    xor edx, edx                 ; hash accumulator

.name_loop:
    movzx ebx, byte [eax]
    test bl, bl
    jz .compare
    ror edx, 13
    add edx, ebx
    and edx, 0xFFFFFFFF
    inc eax
    jmp .name_loop

.compare:
    cmp edx, ebp
    pop edx
    je .found

    inc ecx
    cmp ecx, [eax + 0x18]        ; compare with NumberOfNames
    jb .hash_loop

    xor eax, eax
    jmp .done

.found:
    movzx eax, word [edx + ecx*2]
    mov ecx, [esi + 0x3C]
    mov ecx, [esi + ecx + 0x78]
    mov ecx, [ecx + 0x1C]        ; AddressOfFunctions
    add ecx, esi
    mov eax, [ecx + eax*4]
    add eax, esi

.done:
    pop ecx
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret 4
"""


__all__ = [
    "generate_resolve_function",
    "generate_resolver_x64",
    "generate_resolver_x86",
]
