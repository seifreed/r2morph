"""
Import table obfuscation mutation pass.

Obfuscates the import table by redirecting imports through a jump table,
making static analysis of imported functions more difficult.

Implementation allocates code caves for jump stubs, writes indirect
jump instructions, and patches call-site cross-references.
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass
from r2morph.relocations.cave_finder import CaveFinder, CodeCave

logger = logging.getLogger(__name__)

_X86_CALL_OPCODE = 0xE8
_RELATIVE_CALL_SIZE_BYTES = 5
_SIGNED_32_MIN = -(1 << 31)
_SIGNED_32_MAX = (1 << 31) - 1
_MIN_EXECUTABLE_CAVE_SIZE_BYTES = 8


class ImportTableObfuscationPass(MutationPass):
    """
    Mutation pass that obfuscates the import table.

    This pass creates an indirection layer for imported functions by:
    1. Allocating a new section for the jump table
    2. Creating jump stubs for each imported function
    3. Updating references to use the jump table

    This makes it harder to statically analyze which functions are imported.

    Config options:
        - probability: Probability of obfuscating an import (default: 0.5)
        - max_imports: Maximum imports to obfuscate (default: 50)
        - create_new_section: Whether to create a new section (default: True)
        - section_name: Name for new section (default: ".jmtab")
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="ImportTableObfuscation", config=config)
        self.probability = self.config.get("probability", 0.5)
        self.max_imports = self.config.get("max_imports", 50)
        self.create_new_section = self.config.get("create_new_section", True)
        self.section_name = self.config.get("section_name", ".jmtab")
        self.set_support(
            formats=("ELF", "PE"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "obfuscates import table",
                "creates jump table indirection",
                "may require relocations update",
            ),
        )

    def _get_binary_format(self, binary: Any) -> str:
        """Detect binary format (ELF, PE, etc.)."""
        arch_info = binary.get_arch_info()
        bin_type = str(arch_info.get("type", "")).upper()
        if "ELF" in bin_type:
            return "ELF"
        elif "PE" in bin_type or "COFF" in bin_type:
            return "PE"
        elif "MACH" in bin_type:
            return "Mach-O"
        return bin_type

    def _get_imports(self, binary: Any, binary_format: str) -> list[dict[str, Any]]:
        """Get imports based on binary format."""
        if binary_format == "ELF":
            return self._get_imports_elf(binary)
        elif binary_format == "PE":
            return self._get_imports_pe(binary)
        return []

    def _get_imports_elf(self, binary: Any) -> list[dict[str, Any]]:
        """
        Get imports from ELF binary using relocations.

        Args:
            binary: Any instance

        Returns:
            List of import dictionaries
        """
        imports: list[dict[str, Any]] = []

        try:
            r2 = binary.r2
            if r2 is None:
                return imports
            relocs = r2.cmdj("irj") or []
            for reloc in relocs:
                name = reloc.get("name", "")
                addr = reloc.get("addr", 0)
                if name and addr:
                    imports.append(
                        {
                            "name": name,
                            "address": addr,
                            "type": reloc.get("type", "unknown"),
                            "section": reloc.get("section", ""),
                        }
                    )
        except Exception as e:
            logger.debug(f"Failed to get ELF relocations: {e}")

        if not imports:
            try:
                r2 = binary.r2
                if r2 is None:
                    return imports
                symbols = r2.cmdj("isj") or []
                for sym in symbols:
                    if sym.get("is_imported", False) or sym.get("type", "") == "FUNC":
                        name = sym.get("name", "")
                        addr = sym.get("vaddr", 0)
                        if name and addr:
                            imports.append(
                                {
                                    "name": name,
                                    "address": addr,
                                    "type": "import",
                                    "section": "",
                                }
                            )
            except Exception as e:
                logger.debug(f"Failed to get ELF symbols: {e}")

        return imports

    def _get_imports_pe(self, binary: Any) -> list[dict[str, Any]]:
        """
        Get imports from PE binary.

        Args:
            binary: Any instance

        Returns:
            List of import dictionaries
        """
        imports: list[dict[str, Any]] = []

        try:
            r2 = binary.r2
            if r2 is None:
                return imports
            import_info = r2.cmdj("iij") or []
            for imp in import_info:
                name = imp.get("name", "")
                addr = imp.get("plt", 0) or imp.get("vaddr", 0)
                if name and addr:
                    imports.append(
                        {
                            "name": name,
                            "address": addr,
                            "dll": imp.get("libname", ""),
                            "type": "import",
                            "ordinal": imp.get("ordinal", 0),
                        }
                    )
        except Exception as e:
            logger.debug(f"Failed to get PE imports: {e}")

        return imports

    def _generate_jump_stub_x86_64(self, binary: Any, target_addr: int) -> bytes | None:
        """
        Generate a jump stub for x86_64.

        Args:
            binary: Any instance for assembly
            target_addr: Target address to jump to

        Returns:
            Assembled jump stub bytes or None
        """
        stub = f"jmp 0x{target_addr:x}"
        result = binary.assemble(stub, None)
        return bytes(result) if result else None

    def _find_call_xrefs(self, binary: Any, plt_addr: int) -> list[dict[str, Any]]:
        """
        Find cross-references to an import PLT address that are call instructions.

        Args:
            binary: Binary instance
            plt_addr: PLT address to find references to

        Returns:
            List of xref dicts with call-site addresses
        """
        call_xrefs: list[dict[str, Any]] = []
        try:
            xrefs = binary.r2.cmdj(f"axtj @ {plt_addr}") or []
            for xref in xrefs:
                xref_addr = xref.get("from", 0)
                if not xref_addr:
                    continue
                opcode_bytes = binary.read_bytes(xref_addr, 1)
                if opcode_bytes and opcode_bytes[0] == _X86_CALL_OPCODE:
                    call_xrefs.append(xref)
        except Exception as e:
            logger.debug(f"Failed to get xrefs for 0x{plt_addr:x}: {e}")
        return call_xrefs

    def _patch_call_sites(
        self,
        binary: Any,
        call_xrefs: list[dict[str, Any]],
        stub_addr: int,
    ) -> int:
        """
        Patch call-site xrefs to redirect through the stub.

        Args:
            binary: Binary instance
            call_xrefs: List of call-instruction xrefs
            stub_addr: Address of the jump stub in the cave

        Returns:
            Number of call sites successfully patched
        """
        patched = 0
        for xref in call_xrefs:
            call_site = xref.get("from", 0)
            if not call_site:
                continue
            original_bytes = binary.read_bytes(call_site, _RELATIVE_CALL_SIZE_BYTES)
            if not original_bytes or len(original_bytes) < _RELATIVE_CALL_SIZE_BYTES:
                continue
            new_rel32 = stub_addr - (call_site + _RELATIVE_CALL_SIZE_BYTES)
            if new_rel32 < _SIGNED_32_MIN or new_rel32 > _SIGNED_32_MAX:
                logger.debug(f"Offset out of range for call at 0x{call_site:x} -> stub 0x{stub_addr:x}")
                continue
            patched_call = b"\xe8" + new_rel32.to_bytes(4, "little", signed=True)
            if binary.write_bytes(call_site, patched_call):
                patched += 1
                logger.debug(f"Patched call at 0x{call_site:x} -> stub 0x{stub_addr:x}")
        return patched

    @staticmethod
    def _allocate_stub(
        binary: Any, caves: list[CodeCave], cave_index: int, stub_bytes: bytes
    ) -> tuple[int | None, int]:
        while cave_index < len(caves):
            cave = caves[cave_index]
            if cave.size < len(stub_bytes):
                cave_index += 1
                continue
            stub_address = cave.address
            if not binary.write_bytes(stub_address, stub_bytes):
                logger.debug(f"Failed to write stub at 0x{stub_address:x}")
                cave_index += 1
                continue
            cave.address += len(stub_bytes)
            cave.size -= len(stub_bytes)
            return stub_address, cave_index
        return None, cave_index

    def _obfuscate_import(
        self,
        binary: Any,
        imported: dict[str, Any],
        caves: list[CodeCave],
        cave_index: int,
        binary_format: str,
    ) -> tuple[dict[str, Any] | None, int, bool]:
        name = imported.get("name", "")
        plt_address = imported.get("address", 0)
        if not name or not plt_address:
            return None, cave_index, False
        call_xrefs = self._find_call_xrefs(binary, plt_address)
        if not call_xrefs:
            logger.debug(f"No call xrefs for import {name} at 0x{plt_address:x}, skipping")
            return None, cave_index, False
        stub_bytes = self._generate_jump_stub_x86_64(binary, plt_address)
        if stub_bytes is None:
            logger.debug(f"Failed to generate jump stub for {name}")
            return None, cave_index, False
        stub_address, cave_index = self._allocate_stub(binary, caves, cave_index, stub_bytes)
        if stub_address is None:
            return None, cave_index, True
        patched = self._patch_call_sites(binary, call_xrefs, stub_address)
        if patched == 0:
            return None, cave_index, False
        entry = {
            "name": name,
            "original_address": plt_address,
            "stub_address": stub_address,
            "call_sites_patched": patched,
        }
        self._record_mutation(
            function_address=None,
            start_address=stub_address,
            end_address=stub_address + len(stub_bytes) - 1,
            original_bytes=b"\x00" * len(stub_bytes),
            mutated_bytes=stub_bytes,
            original_disasm=f"import:{name}@0x{plt_address:x}",
            mutated_disasm=f"stub@0x{stub_address:x}->{patched} call sites",
            mutation_kind="import_obfuscation",
            metadata={
                "import_name": name,
                "plt_address": plt_address,
                "stub_address": stub_address,
                "call_sites_patched": patched,
                "format": binary_format,
            },
        )
        logger.debug(f"Obfuscated import {name}: stub@0x{stub_address:x}, {patched} call sites patched")
        return entry, cave_index, False

    @staticmethod
    def _analyze_xrefs(binary: Any) -> None:
        try:
            binary.r2.cmd("aaa")
        except (OSError, RuntimeError) as error:
            logger.warning(
                "r2 'aaa' analysis failed before import obfuscation; xref-based rewriting may be incomplete: %s",
                error,
            )

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply import table obfuscation to the binary.

        Redirects import calls through jump stubs placed in code caves,
        making static analysis of imported functions more difficult.

        Args:
            binary: Binary to obfuscate

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying import table obfuscation")

        binary_format = self._get_binary_format(binary)

        if binary_format not in ("ELF", "PE"):
            logger.warning(f"Import obfuscation not supported for {binary_format}")
            return {"mutations_applied": 0, "skipped": True, "reason": "unsupported format"}

        imports = self._get_imports(binary, binary_format)

        if not imports:
            logger.info("No imports found to obfuscate")
            return {
                "mutations_applied": 0,
                "imports_found": 0,
                "format": binary_format,
            }

        selected = random.sample(imports, min(self.max_imports, len(imports)))

        # Find executable caves for stub placement
        cave_finder = CaveFinder(binary, min_size=16)
        caves = cave_finder.find_caves()
        exec_caves = [c for c in caves if c.is_executable and c.size >= _MIN_EXECUTABLE_CAVE_SIZE_BYTES]

        if not exec_caves:
            logger.warning("No executable code caves found for import obfuscation")
            return {
                "mutations_applied": 0,
                "imports_found": len(imports),
                "imports_obfuscated": 0,
                "format": binary_format,
                "reason": "no_caves",
            }

        # Sort caves largest-first so we consume from the biggest one
        exec_caves.sort(key=lambda c: c.size, reverse=True)

        jump_table_entries: list[dict[str, Any]] = []

        logger.info(
            f"Import obfuscation: processing {len(imports)} imports, "
            f"selected {len(selected)}, caves available: {len(exec_caves)}"
        )

        self._analyze_xrefs(binary)

        if self._session is not None:
            self._create_mutation_checkpoint("import_obfuscation")

        cave_idx = 0

        for imp in selected:
            if random.random() > self.probability:
                continue

            entry, cave_idx, caves_exhausted = self._obfuscate_import(binary, imp, exec_caves, cave_idx, binary_format)
            if caves_exhausted:
                logger.warning("Ran out of code caves for import stubs")
                break
            if entry is not None:
                jump_table_entries.append(entry)

        imports_obfuscated = len(jump_table_entries)
        call_sites_patched = sum(int(entry["call_sites_patched"]) for entry in jump_table_entries)
        if self._validation_manager is not None:
            self._validation_manager.capture_structural_baseline(binary, 0)

        logger.info(
            f"Import obfuscation complete: {imports_obfuscated} imports obfuscated, "
            f"{call_sites_patched} call sites patched"
        )

        return {
            "mutations_applied": imports_obfuscated,
            "imports_found": len(imports),
            "imports_obfuscated": imports_obfuscated,
            "stubs_created": imports_obfuscated,
            "call_sites_patched": call_sites_patched,
            "jump_table_entries": len(jump_table_entries),
            "format": binary_format,
        }
