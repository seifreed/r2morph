"""
Anti-Disassembly - Techniques to confuse disassemblers.

Implements various anti-disassembly techniques:
- False disassembly (overlapping instructions)
- SEH-based obfuscation
- Jump into middle of instruction
- Polyglot code (valid as multiple architectures)
- Opaque predicates that confuse analysis
- Trampoline-based obfuscation

Anti-disassembly makes static analysis difficult by:
- Creating false control flow paths
- Using overlapping instructions
- Exploiting differences between linear and recursive disassembly
- Injecting SEH handlers that confuse analysis tools
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.anti_disassembly_snippets import (
    ALL_ANTI_DISASM_X64,
    FALSE_BRANCH_X64,
    JUMP_MIDDLE_X64,
    OVERLAPPING_X64,
    POLYGLOT_X64_86,
    SEH_BASED_X64,
    SEH_BASED_X86,
    TRAMPOLINE_X64,
    AntiDisasmSnippet,
    AntiDisasmType,
    generate_false_disasm_sequence,
    generate_opaque_predicate_x64,
    generate_sled_obfuscation,
)
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class AntiDisassemblyPass(MutationPass):
    """
    Mutation pass that injects anti-disassembly techniques.

    Inserts code sequences that confuse disassemblers while
    maintaining correct execution semantics.

    Config options:
        - probability: Probability of injecting at each point (default: 0.3)
        - techniques: List of techniques to use (default: all)
        - seh_enabled: Enable SEH-based techniques (default: False, dangerous)
        - max_injections: Maximum injections per function (default: 5)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="AntiDisassembly", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.techniques = self.config.get("techniques", list(AntiDisasmType))
        self.seh_enabled = self.config.get("seh_enabled", False)
        self.max_injections = self.config.get("max_injections", 5)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "injects anti-disassembly techniques",
                "confuses linear and recursive disassemblers",
                "SEH techniques may cause issues on some platforms",
            ),
        )

    def _get_snippets_for_arch(self, arch: str) -> list[AntiDisasmSnippet]:
        """Get anti-disasm snippets for architecture."""
        if arch == "x64":
            snippets = ALL_ANTI_DISASM_X64.copy()
        else:
            snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64.copy()

        if not self.seh_enabled:
            snippets = [s for s in snippets if s.disasm_type != AntiDisasmType.SEH_BASED]

        return snippets

    def _inject_snippet(self, binary: Any, addr: int, snippet: AntiDisasmSnippet) -> bool:
        """Inject a snippet at the given address."""
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return bool(binary.write_bytes(addr, snippet_bytes))
        except Exception as e:
            logger.debug(f"Failed to inject snippet: {e}")
            return False

    def _inject_overlapping(self, binary: Any, addr: int) -> bool:
        """Inject overlapping instruction pattern."""
        snippet = random.choice(OVERLAPPING_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return bool(binary.write_bytes(addr, snippet_bytes))
        except Exception as e:
            logger.debug(f"Failed to inject overlapping pattern: {e}")
            return False

    def _inject_false_branch(self, binary: Any, addr: int) -> bool:
        """Inject false branch pattern."""
        snippet = random.choice(FALSE_BRANCH_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return bool(binary.write_bytes(addr, snippet_bytes))
        except Exception as e:
            logger.debug(f"Failed to inject false branch pattern: {e}")
            return False

    def _inject_jump_middle(self, binary: Any, addr: int) -> bool:
        """Inject jump into middle of instruction."""
        snippet = random.choice(JUMP_MIDDLE_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return bool(binary.write_bytes(addr, snippet_bytes))
        except Exception as e:
            logger.debug(f"Failed to inject jump-middle pattern: {e}")
            return False

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply anti-disassembly techniques.

        Args:
            binary: Any to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying anti-disassembly techniques")

        functions = binary.get_functions()
        injected_count = 0
        injections_by_type = {t: 0 for t in AntiDisasmType}

        arch_info = binary.get_arch_info()
        arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"
        snippets = self._get_snippets_for_arch(arch)

        for func in functions:
            if injected_count >= self.max_injections * len(functions):
                break

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            for block in blocks:
                if random.random() > 0.3:
                    continue

                block_addr = block.get("addr", 0)
                snippet = random.choice(snippets)

                mutation_checkpoint = self._create_mutation_checkpoint("anti_disasm")
                baseline = {}
                if self._validation_manager is not None:
                    baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                original_bytes = binary.read_bytes(block_addr, len(snippet.bytes_hex) // 2)
                if original_bytes and self._inject_snippet(binary, block_addr, snippet):
                    mutated_bytes = binary.read_bytes(block_addr, len(snippet.bytes_hex) // 2)
                    self._record_mutation(
                        function_address=func["addr"],
                        start_address=block_addr,
                        end_address=block_addr + len(snippet.bytes_hex) // 2 - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=mutated_bytes if mutated_bytes else bytes.fromhex(snippet.bytes_hex),
                        original_disasm="original_bytes",
                        mutated_disasm=snippet.description,
                        mutation_kind="anti_disassembly",
                        metadata={
                            "disasm_type": snippet.disasm_type.value,
                            "structural_baseline": baseline,
                        },
                    )

                    if self._validation_manager is not None:
                        outcome = self._validation_manager.validate_mutation(
                            binary, self._records[-1].to_dict() if self._records else {}
                        )
                        if not outcome.passed and mutation_checkpoint is not None:
                            self._rollback_mutation(binary, mutation_checkpoint)
                            continue

                    injections_by_type[snippet.disasm_type] += 1
                    injected_count += 1

                logger.debug(f"Injected {snippet.disasm_type.value} at 0x{block.get('addr', 0):x}")

        return {
            "total_injections": injected_count,
            "injections_by_type": {t.value: count for t, count in injections_by_type.items()},
            "seh_enabled": self.seh_enabled,
            "architecture": arch,
        }


__all__ = [
    "ALL_ANTI_DISASM_X64",
    "AntiDisassemblyPass",
    "AntiDisasmSnippet",
    "AntiDisasmType",
    "FALSE_BRANCH_X64",
    "JUMP_MIDDLE_X64",
    "OVERLAPPING_X64",
    "POLYGLOT_X64_86",
    "SEH_BASED_X64",
    "SEH_BASED_X86",
    "TRAMPOLINE_X64",
    "generate_false_disasm_sequence",
    "generate_opaque_predicate_x64",
    "generate_sled_obfuscation",
]
