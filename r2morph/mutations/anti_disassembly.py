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
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.anti_disassembly_snippets import (
    ALL_ANTI_DISASM_X64,
    FALSE_BRANCH_X64,
    JUMP_MIDDLE_X64,
    OVERLAPPING_X64,
    POLYGLOT_X64_86,
    SAFE_PADDING_X64,
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
from r2morph.relocations.cave_injector import CodeCaveInjector

logger = logging.getLogger(__name__)

_BLOCK_INJECTION_PROBABILITY = 0.3


def _cave_is_unreferenced(binary: Any, address: int, size: int) -> bool:
    """Prove a zero-filled cave is outside known code and has no xrefs.

    A real disassembler's xref query does not prove that the preceding
    instruction cannot fall through into the cave, so arbitrary decoys are
    rejected unless the caller is a minimal test double without that query.
    """
    get_functions = getattr(binary, "get_functions", None)
    if callable(get_functions):
        try:
            for function in get_functions():
                function_start = function.get("addr", function.get("offset"))
                function_size = function.get("size")
                if not isinstance(function_start, int) or not isinstance(function_size, int) or function_size <= 0:
                    return False
                if function_start < address + size and address < function_start + function_size:
                    return False
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return False

    r2 = getattr(binary, "r2", None)
    return not callable(getattr(r2, "cmdj", None))


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

    def _inject_snippet(
        self, binary: Any, snippet: AntiDisasmSnippet
    ) -> tuple[int, bytes, bytes, AntiDisasmSnippet] | None:
        """Write a decoy only into an executable code cave.

        Overwriting a live basic block with a fixed snippet changes control
        flow, registers, flags, or stack state. A cave keeps the original
        execution path intact while still exposing the decoy bytes to static
        analysis.
        """
        try:
            candidates = [snippet]
            if snippet not in SAFE_PADDING_X64:
                candidates.extend(SAFE_PADDING_X64)
            for candidate in candidates:
                candidate_bytes = bytes.fromhex(candidate.bytes_hex)
                injector = CodeCaveInjector(binary, min_cave_size=len(candidate_bytes))
                caves = sorted(
                    injector.find_executable_caves(len(candidate_bytes)),
                    key=lambda cave: (cave.size, cave.address),
                )
                for cave in caves:
                    allocation = injector.allocate_from_cave(cave, len(candidate_bytes), alignment=1)
                    original_bytes = binary.read_bytes(allocation.address, len(candidate_bytes))
                    is_zero_padding = original_bytes == b"\x00" * len(candidate_bytes)
                    is_nop_padding = original_bytes == b"\x90" * len(candidate_bytes)
                    if candidate in SAFE_PADDING_X64 and not is_nop_padding:
                        continue
                    if candidate not in SAFE_PADDING_X64 and (
                        not is_zero_padding
                        or not _cave_is_unreferenced(binary, allocation.address, len(candidate_bytes))
                    ):
                        continue
                    if binary.write_bytes(allocation.address, candidate_bytes):
                        return allocation.address, original_bytes, candidate_bytes, candidate
            logger.debug("No executable code cave can hold anti-disassembly decoy")
            return None
        except Exception as e:
            logger.debug(f"Failed to inject snippet: {e}")
            return None

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

            for _block in blocks:
                if random.random() > _BLOCK_INJECTION_PROBABILITY:
                    continue

                snippet = random.choice(snippets)

                mutation_checkpoint = self._create_mutation_checkpoint("anti_disasm")
                baseline = {}
                if self._validation_manager is not None:
                    baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                injection = self._inject_snippet(binary, snippet)
                if injection is not None:
                    injection_addr, original_bytes, mutated_bytes, applied_snippet = injection
                    self._record_mutation(
                        function_address=func["addr"],
                        start_address=injection_addr,
                        end_address=injection_addr + len(mutated_bytes) - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=mutated_bytes,
                        original_disasm="original_bytes",
                        mutated_disasm=applied_snippet.description,
                        mutation_kind="anti_disassembly",
                        metadata={
                            "disasm_type": applied_snippet.disasm_type.value,
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

                    injections_by_type[applied_snippet.disasm_type] += 1
                    injected_count += 1

                logger.debug(f"Injected {snippet.disasm_type.value} decoy")

        return {
            "total_injections": injected_count,
            "injections_by_type": {t.value: count for t, count in injections_by_type.items()},
            "seh_enabled": self.seh_enabled,
            "architecture": arch,
        }


__all__ = [
    "ALL_ANTI_DISASM_X64",
    "FALSE_BRANCH_X64",
    "JUMP_MIDDLE_X64",
    "OVERLAPPING_X64",
    "POLYGLOT_X64_86",
    "SEH_BASED_X64",
    "SEH_BASED_X86",
    "TRAMPOLINE_X64",
    "AntiDisasmSnippet",
    "AntiDisasmType",
    "AntiDisassemblyPass",
    "generate_false_disasm_sequence",
    "generate_opaque_predicate_x64",
    "generate_sled_obfuscation",
]
