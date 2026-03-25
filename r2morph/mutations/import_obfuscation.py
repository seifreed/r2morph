"""
Import table obfuscation mutation pass.

Obfuscates the import table by redirecting imports through a jump table,
making static analysis of imported functions more difficult.

Implementation allocates code caves for jump stubs, writes indirect
jump instructions, and patches call-site cross-references.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from r2morph.mutations.base import MutationPass
from r2morph.relocations.cave_finder import CaveFinder

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


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

    def _generate_jump_stub_x86(self, binary: Any, target_addr: int) -> bytes | None:
        """
        Generate a jump stub for x86.

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
                if opcode_bytes and opcode_bytes[0] == 0xE8:
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
            original_bytes = binary.read_bytes(call_site, 5)
            if not original_bytes or len(original_bytes) < 5:
                continue
            new_rel32 = stub_addr - (call_site + 5)
            if new_rel32 < -2147483648 or new_rel32 > 2147483647:
                logger.debug(f"Offset out of range for call at 0x{call_site:x} -> stub 0x{stub_addr:x}")
                continue
            patched_call = b"\xe8" + new_rel32.to_bytes(4, "little", signed=True)
            if binary.write_bytes(call_site, patched_call):
                patched += 1
                logger.debug(f"Patched call at 0x{call_site:x} -> stub 0x{stub_addr:x}")
        return patched

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
        exec_caves = [c for c in caves if c.is_executable and c.size >= 8]

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

        imports_obfuscated = 0
        stubs_created = 0
        call_sites_patched = 0
        jump_table_entries: list[dict[str, Any]] = []

        logger.info(
            f"Import obfuscation: processing {len(imports)} imports, "
            f"selected {len(selected)}, caves available: {len(exec_caves)}"
        )

        # Ensure r2 analysis is done for xrefs
        try:
            binary.r2.cmd("aaa")
        except Exception:
            pass

        if self._session is not None:
            self._create_mutation_checkpoint("import_obfuscation")

        cave_idx = 0

        for imp in selected:
            if random.random() > self.probability:
                continue

            name = imp.get("name", "")
            plt_addr = imp.get("address", 0)

            if not name or not plt_addr:
                continue

            # Find call-site xrefs to this import
            call_xrefs = self._find_call_xrefs(binary, plt_addr)
            if not call_xrefs:
                logger.debug(f"No call xrefs for import {name} at 0x{plt_addr:x}, skipping")
                continue

            # Generate a jump stub targeting the original PLT address
            stub_bytes = self._generate_jump_stub_x86_64(binary, plt_addr)
            if stub_bytes is None:
                logger.debug(f"Failed to generate jump stub for {name}")
                continue

            stub_size = len(stub_bytes)

            # Find a cave with enough room
            allocated = False
            while cave_idx < len(exec_caves):
                cave = exec_caves[cave_idx]
                if cave.size >= stub_size:
                    stub_addr = cave.address
                    # Write the stub into the cave
                    if not binary.write_bytes(stub_addr, stub_bytes):
                        logger.debug(f"Failed to write stub at 0x{stub_addr:x}")
                        cave_idx += 1
                        continue
                    # Advance the cave pointer
                    cave.address += stub_size
                    cave.size -= stub_size
                    allocated = True
                    break
                cave_idx += 1

            if not allocated:
                logger.warning("Ran out of code caves for import stubs")
                break

            # Patch all call sites to go through the stub
            patched = self._patch_call_sites(binary, call_xrefs, stub_addr)

            if patched > 0:
                stubs_created += 1
                call_sites_patched += patched
                imports_obfuscated += 1

                jump_table_entries.append(
                    {
                        "name": name,
                        "original_address": plt_addr,
                        "stub_address": stub_addr,
                        "call_sites_patched": patched,
                    }
                )

                self._record_mutation(
                    function_address=None,
                    start_address=stub_addr,
                    end_address=stub_addr + stub_size - 1,
                    original_bytes=b"\x00" * stub_size,
                    mutated_bytes=stub_bytes,
                    original_disasm=f"import:{name}@0x{plt_addr:x}",
                    mutated_disasm=f"stub@0x{stub_addr:x}->{patched} call sites",
                    mutation_kind="import_obfuscation",
                    metadata={
                        "import_name": name,
                        "plt_address": plt_addr,
                        "stub_address": stub_addr,
                        "call_sites_patched": patched,
                        "format": binary_format,
                    },
                )

                logger.debug(f"Obfuscated import {name}: stub@0x{stub_addr:x}, " f"{patched} call sites patched")

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
            "stubs_created": stubs_created,
            "call_sites_patched": call_sites_patched,
            "jump_table_entries": len(jump_table_entries),
            "format": binary_format,
        }
