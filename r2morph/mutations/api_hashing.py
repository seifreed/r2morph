"""
API Hashing - Import resolution by hash.

Resolves Windows API functions by hash instead of name,
evading static analysis of import tables and
making dynamic analysis harder.

This technique is commonly used in malware to:
- Hide APIs used (CreateFile, VirtualAlloc, etc.)
- Evade import table analysis
- Make static import enumeration useless

Hash resolution uses PEB walking to find kernel32.dll
and then walks export tables to resolve functions by hash.

Example:
    Original:    call [imp_CreateFileA]
    Hashed:      mov rax, 0x7D8A3F21  ; hash("CreateFileA")
                 call resolve_by_hash
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from r2morph.mutations.base import MutationPass

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

COMMON_WINDOWS_APIS = [
    "CreateFileA",
    "CreateFileW",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "ReadFile",
    "WriteFile",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "NtQueryInformationProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "VirtualQuery",
    "CreateProcessA",
    "CreateProcessW",
    "CreateRemoteThread",
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "TerminateProcess",
    "WaitForSingleObject",
    "CloseHandle",
    "HeapCreate",
    "HeapAlloc",
    "HeapFree",
    "GetProcessHeap",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegQueryValueExA",
    "RegSetValueExA",
    "RegCloseKey",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "SetFileAttributesA",
    "SetFileAttributesW",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "CopyFileA",
    "CopyFileW",
    "CreateDirectoryA",
    "CreateDirectoryW",
    "RemoveDirectoryA",
    "RemoveDirectoryW",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FindClose",
    "GetSystemDirectoryA",
    "GetSystemDirectoryW",
    "GetWindowsDirectoryA",
    "GetWindowsDirectoryW",
    "GetCurrentDirectoryA",
    "GetCurrentDirectoryW",
    "SetCurrentDirectoryA",
    "SetCurrentDirectoryW",
    "GetFileSize",
    "SetFilePointer",
    "GetTickCount",
    "QueryPerformanceCounter",
    "Sleep",
    "ExitProcess",
    "ExitThread",
    "malloc",
    "free",
]

COMMON_LINUX_APIS = [
    "open",
    "read",
    "write",
    "close",
    "mmap",
    "munmap",
    "mprotect",
    "execve",
    "fork",
    "clone",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "recv",
    "dlopen",
    "dlsym",
    "dlclose",
    "malloc",
    "free",
    "realloc",
    "calloc",
    "pthread_create",
    "pthread_join",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
]


def ror32(value: int, count: int) -> int:
    """Rotate right 32-bit value."""
    count = count % 32
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def rol32(value: int, count: int) -> int:
    """Rotate left 32-bit value."""
    count = count % 32
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def hash_ror13(name: str) -> int:
    """
    Calculate ROR13 hash of API name.

    This is the most common API hashing algorithm, used by:
    - Metasploit shikata_ga_nai
    - Many shellcode loaders
    - Various malware families

    Args:
        name: API name (case-insensitive)

    Returns:
        32-bit hash value
    """
    h = 0
    for c in name.lower():
        h = ror32(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_ror7(name: str) -> int:
    """
    Calculate ROR7 hash variant.

    Alternative rotation amount.

    Args:
        name: API name (case-insensitive)

    Returns:
        32-bit hash value
    """
    h = 0
    for c in name.lower():
        h = ror32(h, 7)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_djb2(name: str) -> int:
    """
    Calculate DJB2 hash.

    Simple and fast hash function.

    Args:
        name: API name

    Returns:
        32-bit hash value
    """
    h = 5381
    for c in name:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def hash_fnv1a(name: str) -> int:
    """
    Calculate FNV-1a hash.

    Fowler-Noll-Vo hash, variant 1a.

    Args:
        name: API name

    Returns:
        32-bit hash value
    """
    h = 2166136261
    for c in name.lower():
        h ^= ord(c)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def hash_crc32(name: str) -> int:
    """Calculate CRC32 hash of a string."""
    import binascii

    return binascii.crc32(name.lower().encode()) & 0xFFFFFFFF


HASH_ALGORITHMS = {
    "ror13": hash_ror13,
    "ror7": hash_ror7,
    "djb2": hash_djb2,
    "fnv1a": hash_fnv1a,
    "crc32": hash_crc32,
}


def generate_resolver_x64(hash_value: int, dll_name: str = "kernel32.dll") -> str:
    """
    Generate x64 assembly for PEB-based API resolution by hash.

    This generates code that:
    1. Walks PEB to find DLL base
    2. Walks export table to find function by hash
    3. Returns function pointer in RAX

    Args:
        hash_value: The hash to resolve
        dll_name: DLL name for comments

    Returns:
        Assembly code string
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

    Args:
        hash_value: The hash to resolve
        dll_name: DLL name for comments

    Returns:
        Assembly code string
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

    Args:
        arch: Architecture ("x64" or "x86")

    Returns:
        Assembly code string
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
    mov r13d, [rdi + 0x20]        ; AddressOfNames RVA
    add r13, rsi
    mov r11d, [rdi + 0x24]        ; AddressOfNameOrdinals RVA
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
    else:
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


class APIHashingPass(MutationPass):
    """
    Mutation pass that replaces direct imports with hash-based resolution.

    Transforms:
        call [imp_CreateFileA]

    Into:
        mov rcx, 0xHASH
        call resolve_api_hash
        call rax

    This evades import table analysis by hiding API names.
    """

    APIS_TO_HASH = COMMON_WINDOWS_APIS + COMMON_LINUX_APIS

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="APIHashing", config=config)
        self.hash_algorithm = self.config.get("hash_algorithm", "ror13")
        self.arch = self.config.get("arch", "x64")
        self.include_resolver = self.config.get("include_resolver", True)
        self.api_list = self.config.get("api_list", self.APIS_TO_HASH)
        self.generate_stubs = self.config.get("generate_stubs", True)
        self.set_support(
            formats=("PE", "ELF"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "replaces import table entries with hash resolution",
                "generates hash lookup stubs",
                "supports ROR13, ROR7, DJB2, FNV1a, CRC32",
            ),
        )

    def _hash_api(self, api_name: str) -> int:
        """Hash an API name using the configured algorithm."""
        algo = HASH_ALGORITHMS.get(self.hash_algorithm, hash_ror13)
        return algo(api_name)

    def _find_imports(self, binary: Any) -> list[dict[str, Any]]:
        """Find import entries in the binary."""
        imports: list[dict[str, Any]] = []

        try:
            r2 = binary.r2
            if r2 is None:
                return imports

            import_data = r2.cmdj("iij") or []

            for imp in import_data:
                name = imp.get("name", "")
                addr = imp.get("plt", imp.get("addr", 0))
                if name and addr:
                    imports.append(
                        {
                            "name": name,
                            "address": addr,
                            "type": imp.get("type", "UNKNOWN"),
                            "dll": imp.get("libname", "unknown"),
                        }
                    )

        except Exception as e:
            logger.debug(f"Failed to get imports: {e}")

        return imports

    def _hash_known_api(self, api_name: str) -> int | None:
        """Check if API is in our list and return its hash."""
        api_lower = api_name.lower()
        for known in self.api_list:
            if known.lower() == api_lower:
                return self._hash_api(known)
        return None

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply API hashing mutation.

        Args:
            binary: Any to mutate

        Returns:
            Statistics dictionary

        NOTE: This is a PLACEHOLDER. Full implementation requires:
        - Patching PLT entries or import addresses
        - Writing hash resolver stubs to binary
        - Updating import table references
        """
        self._reset_random()
        logger.info("Applying API hashing mutation")
        logger.warning(
            "API hashing PLACEHOLDER: calculating hashes but NOT modifying binary. "
            "Full implementation needed for actual hashing."
        )

        imports = self._find_imports(binary)
        hashed_count = 0
        skipped_count = 0
        resolver_generated = False

        for imp in imports:
            api_name = imp.get("name", "")
            addr = imp.get("address", 0)

            if addr == 0:
                continue

            hash_value = self._hash_known_api(api_name)
            if hash_value is None:
                skipped_count += 1
                continue

            if self.generate_stubs:
                generate_resolver_x64(hash_value, imp.get("dll", "unknown"))
            else:
                pass

            hashed_count += 1
            logger.debug(f"Hashed {api_name} -> 0x{hash_value:08X}")

        if self.include_resolver and hashed_count > 0:
            generate_resolve_function(self.arch)
            logger.debug(f"Generated generic resolver for {self.arch}")
            resolver_generated = True

        if self._session is not None:
            self._create_mutation_checkpoint("api_hashing")
        else:
            pass

        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, 0)

        self._record_mutation(
            function_address=None,
            start_address=0,
            end_address=0,
            original_bytes=b"",
            mutated_bytes=b"",
            original_disasm="import_table",
            mutated_disasm=f"api_hashing (placeholder - {hashed_count} APIs hashed)",
            mutation_kind="api_hashing",
            metadata={
                "imports_found": len(imports),
                "imports_hashed": hashed_count,
                "imports_skipped": skipped_count,
                "resolver_generated": resolver_generated,
                "hash_algorithm": self.hash_algorithm,
                "architecture": self.arch,
                "placeholder": True,
                "structural_baseline": baseline,
            },
        )

        return {
            "imports_found": len(imports),
            "imports_hashed": hashed_count,
            "imports_skipped": skipped_count,
            "resolver_generated": resolver_generated,
            "hash_algorithm": self.hash_algorithm,
            "architecture": self.arch,
            "placeholder": True,
        }

    def get_api_hashes(self) -> dict[str, int]:
        """Get hashes for all APIs in the list."""
        return {api: self._hash_api(api) for api in self.api_list}

    def generate_hash_table(self) -> str:
        """Generate C-style hash table for all known APIs."""
        lines = ["// API Hash Table", f"// Algorithm: {self.hash_algorithm}", ""]
        lines.append("static struct {")
        lines.append("    uint32_t hash;")
        lines.append("    const char *name;")
        lines.append("} api_hashes[] = {")

        for api in sorted(self.api_list):
            h = self._hash_api(api)
            lines.append(f'    {{ 0x{h:08X}, "{api}" }},')

        lines.append("};")
        return "\n".join(lines)
