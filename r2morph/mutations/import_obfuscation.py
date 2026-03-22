"""
Import table obfuscation mutation pass.

Obfuscates the import table by redirecting imports through a jump table,
making static analysis of imported functions more difficult.

NOTE: This is a PLACEHOLDER implementation. The apply() method currently
only plans the obfuscation but does NOT modify the binary. Full implementation
requires:
1. Allocating space for jump table (new section or cave)
2. Writing jump stubs to the allocated space
3. Patching import address references to point to jump stubs
4. Updating relocations/PLT entries as needed

TODO: Implement actual binary modification.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

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

    def _get_imports_elf(self, binary: Binary) -> list[dict[str, Any]]:
        """
        Get imports from ELF binary using relocations.

        Args:
            binary: Binary instance

        Returns:
            List of import dictionaries
        """
        imports = []

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

    def _get_imports_pe(self, binary: Binary) -> list[dict[str, Any]]:
        """
        Get imports from PE binary.

        Args:
            binary: Binary instance

        Returns:
            List of import dictionaries
        """
        imports = []

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

    def _generate_jump_stub_x86_64(self, binary: Binary, target_addr: int) -> bytes | None:
        """
        Generate a jump stub for x86_64.

        Args:
            binary: Binary instance for assembly
            target_addr: Target address to jump to

        Returns:
            Assembled jump stub bytes or None
        """
        stub = f"jmp 0x{target_addr:x}"
        result = binary.assemble(stub, None)
        return bytes(result) if result else None

    def _generate_jump_stub_x86(self, binary: Binary, target_addr: int) -> bytes | None:
        """
        Generate a jump stub for x86.

        Args:
            binary: Binary instance for assembly
            target_addr: Target address to jump to

        Returns:
            Assembled jump stub bytes or None
        """
        stub = f"jmp 0x{target_addr:x}"
        result = binary.assemble(stub, None)
        return bytes(result) if result else None

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply import table obfuscation to the binary.

        Args:
            binary: Binary to obfuscate

        Returns:
            Statistics dictionary

        NOTE: This is a PLACEHOLDER. Full implementation requires:
        - Allocating jump table space in binary
        - Writing jump stubs to allocated space
        - Patching import references
        - Updating relocations/PLT entries
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

        imports_obfuscated = 0
        stubs_created = 0
        jump_table_entries = []

        logger.info(f"Import obfuscation: processing {len(imports)} imports, selected {len(selected)}")
        logger.warning(
            "Import obfuscation PLACEHOLDER: analyzing imports but NOT modifying binary. "
            "Full implementation needed for actual obfuscation."
        )

        for imp in selected:
            if random.random() > self.probability:
                continue

            name = imp.get("name", "")
            addr = imp.get("address", 0)

            if not name or not addr:
                continue

            try:
                jump_table_entries.append(
                    {
                        "name": name,
                        "original_address": addr,
                        "import_info": imp,
                    }
                )
                stubs_created += 1

            except Exception as e:
                logger.debug(f"Failed to create jump stub for {name}: {e}")
                continue

        if self._session is not None:
            mutation_checkpoint = self._create_mutation_checkpoint("import_obfuscation")
        else:
            mutation_checkpoint = None

        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, 0)

        record = self._record_mutation(
            function_address=None,
            start_address=0,
            end_address=0,
            original_bytes=b"",
            mutated_bytes=b"",
            original_disasm="import_table",
            mutated_disasm=f"import_table_obfuscated (placeholder - {stubs_created} entries planned)",
            mutation_kind="import_obfuscation",
            metadata={
                "imports_count": len(imports),
                "imports_obfuscated": stubs_created,
                "jump_table_entries": len(jump_table_entries),
                "format": binary_format,
                "placeholder": True,
                "structural_baseline": baseline,
            },
        )

        imports_obfuscated = stubs_created

        logger.info(f"Import obfuscation analysis complete: {imports_obfuscated} imports planned for obfuscation")

        return {
            "mutations_applied": imports_obfuscated,
            "imports_found": len(imports),
            "imports_obfuscated": imports_obfuscated,
            "stubs_created": stubs_created,
            "jump_table_entries": len(jump_table_entries),
            "format": binary_format,
            "placeholder": True,
        }
