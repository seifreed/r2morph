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
                 call rax
"""

from __future__ import annotations

import logging
from typing import Any

from r2morph.mutations import api_hashing_hashes as _hashes
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolve_function as _generate_resolve_function,
)
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolver_x64 as _generate_resolver_x64,
)
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolver_x86 as _generate_resolver_x86,
)
from r2morph.mutations.base import MutationPass
from r2morph.relocations.cave_finder import CaveFinder, CodeCave

logger = logging.getLogger(__name__)

_SIGNED_32_MIN = -(1 << 31)
_SIGNED_32_MAX = (1 << 31) - 1

COMMON_WINDOWS_APIS = _hashes.COMMON_WINDOWS_APIS
COMMON_LINUX_APIS = _hashes.COMMON_LINUX_APIS
HASH_ALGORITHMS = _hashes.HASH_ALGORITHMS
hash_ror13 = _hashes.hash_ror13
hash_ror7 = _hashes.hash_ror7
hash_djb2 = _hashes.hash_djb2
hash_fnv1a = _hashes.hash_fnv1a
hash_crc32 = _hashes.hash_crc32
ror32 = _hashes.ror32
rol32 = _hashes.rol32


def generate_resolver_x64(hash_value: int, dll_name: str = "kernel32.dll") -> str:
    return _generate_resolver_x64(hash_value, dll_name)


def generate_resolver_x86(hash_value: int, dll_name: str = "kernel32.dll") -> str:
    return _generate_resolver_x86(hash_value, dll_name)


def generate_resolve_function(arch: str = "x64") -> str:
    return _generate_resolve_function(arch)


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

    @staticmethod
    def _allocate_stub(caves: list[CodeCave], cave_index: int, stub_size: int) -> tuple[int | None, int]:
        while cave_index < len(caves):
            cave = caves[cave_index]
            if cave.size >= stub_size:
                caves[cave_index] = CodeCave(
                    address=cave.address + stub_size,
                    size=cave.size - stub_size,
                    section=cave.section,
                    is_executable=cave.is_executable,
                )
                return cave.address, cave_index
            cave_index += 1
        return None, cave_index

    @staticmethod
    def _build_stub(api_name: str, hash_value: int, plt_address: int, cave_address: int) -> bytes | None:
        jump_offset = plt_address - (cave_address + 10)
        if not _SIGNED_32_MIN <= jump_offset <= _SIGNED_32_MAX:
            logger.debug(f"Stub jump offset out of range for {api_name} (cave 0x{cave_address:x})")
            return None
        load_hash = b"\xb8" + (hash_value & 0xFFFFFFFF).to_bytes(4, "little")
        return load_hash + b"\xe9" + jump_offset.to_bytes(4, "little", signed=True)

    @staticmethod
    def _find_xrefs(binary: Any, plt_address: int) -> list[dict[str, Any]]:
        if binary.r2 is None:
            return []
        try:
            return binary.r2.cmdj(f"axtj @ {plt_address}") or []
        except (ValueError, OSError, BrokenPipeError, RuntimeError):
            return []

    @staticmethod
    def _patch_call_sites(binary: Any, xrefs: list[dict[str, Any]], cave_address: int) -> list[dict[str, str]]:
        patched_sites = []
        for xref in xrefs:
            call_site = xref.get("from", 0)
            original_call = binary.read_bytes(call_site, 5) if call_site else b""
            if not original_call or original_call[0:1] != b"\xe8":
                continue
            new_offset = cave_address - (call_site + 5)
            if not _SIGNED_32_MIN <= new_offset <= _SIGNED_32_MAX:
                logger.debug(f"Call-site offset out of range for call at 0x{call_site:x}")
                continue
            patched_call = b"\xe8" + new_offset.to_bytes(4, "little", signed=True)
            if binary.write_bytes(call_site, patched_call):
                patched_sites.append(
                    {
                        "address": hex(call_site),
                        "original_bytes": original_call.hex(),
                        "patched_bytes": patched_call.hex(),
                    }
                )
        return patched_sites

    def _apply_hashed_import(
        self, binary: Any, imported: dict[str, Any], hash_value: int, caves: list[CodeCave], cave_index: int
    ) -> tuple[bool, int]:
        stub_size = 10
        api_name = imported.get("name", "")
        plt_address = imported.get("address", 0)
        cave_address, cave_index = self._allocate_stub(caves, cave_index, stub_size)
        if cave_address is None:
            return False, cave_index
        stub_bytes = self._build_stub(api_name, hash_value, plt_address, cave_address)
        if stub_bytes is None:
            return False, cave_index
        original_cave = binary.read_bytes(cave_address, stub_size)
        if not original_cave:
            logger.debug(f"Skipping API hashing for {api_name}: cannot read cave bytes at 0x{cave_address:x}")
            return False, cave_index
        if not binary.write_bytes(cave_address, stub_bytes):
            return False, cave_index
        patched_sites = self._patch_call_sites(binary, self._find_xrefs(binary, plt_address), cave_address)
        if not patched_sites:
            return False, cave_index
        self._record_mutation(
            function_address=None,
            start_address=cave_address,
            end_address=cave_address + stub_size,
            original_bytes=original_cave,
            mutated_bytes=stub_bytes,
            original_disasm=f"import {api_name} @ 0x{plt_address:x}",
            mutated_disasm=f"mov eax, 0x{hash_value:08x}; jmp 0x{plt_address:x}",
            mutation_kind="api_hashing",
            metadata={"patched_call_sites": patched_sites},
        )
        logger.debug(f"Hashed {api_name} -> 0x{hash_value:08X} ({len(patched_sites)} call sites patched)")
        return True, cave_index

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply API hashing mutation.

        For each hashable import, writes a small trampoline stub to a code
        cave that stores the hash as an immediate value before jumping to
        the original PLT entry. Call sites are patched to go through the
        trampoline, obscuring direct PLT references in static analysis.
        """
        self._reset_random()
        logger.info("Applying API hashing mutation")

        imports = self._find_imports(binary)
        hashed_count = 0
        skipped_count = 0

        caves = CaveFinder(binary).find_caves()
        cave_idx = 0

        if self._session is not None:
            self._create_mutation_checkpoint("api_hashing")

        for imp in imports:
            api_name = imp.get("name", "")
            plt_addr = imp.get("address", 0)
            if plt_addr == 0:
                continue

            hash_value = self._hash_known_api(api_name)
            if hash_value is None:
                skipped_count += 1
                continue

            applied, cave_idx = self._apply_hashed_import(binary, imp, hash_value, caves, cave_idx)
            if applied:
                hashed_count += 1

        return {
            "imports_found": len(imports),
            "imports_hashed": hashed_count,
            "imports_skipped": skipped_count,
            "hash_algorithm": self.hash_algorithm,
            "architecture": self.arch,
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
