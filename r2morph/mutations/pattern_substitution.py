"""
Pattern-based instruction substitution mutation pass.

Wires the pattern-pool subsystem (``pattern_pool`` + ``pattern_generators``)
into the mutation pipeline through :class:`PatternMatchIntegration`. It detects
multi-form instruction patterns (zeroing idioms, inc/dec, small add/sub, …) and
replaces a matched instruction with a semantically equivalent alternative.

Replacements that fit within the original instruction's byte length are applied
and NOP-padded back to the original size, so existing code layout and relocations
are never disturbed. Replacements larger than the original are skipped (they need
cave/relocation support). Identity replacements (same bytes) are skipped.

Pattern-pool equivalences may diverge in condition flags, so this pass is marked
``experimental`` and relies on the pipeline's structural + runtime validation to
reject and roll back any substitution that does not preserve behavior on the
sampled inputs.
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import ARCH_BITS_64
from r2morph.mutations.base import MutationPass
from r2morph.mutations.pattern_integration import PatternMatchIntegration

logger = logging.getLogger(__name__)

MINIMUM_FUNCTION_SIZE = 16


class PatternSubstitutionPass(MutationPass):
    """Substitute instructions using the pattern-pool equivalence subsystem.

    Config options:
        - probability: Probability of applying a matched substitution (default 0.7)
        - max_substitutions_per_function: Cap per function (default 10)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="PatternSubstitution", config=config)
        self.probability = self.config.get("probability", 0.7)
        self.max_substitutions = self.config.get("max_substitutions_per_function", 10)
        self._integration = PatternMatchIntegration()
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural", "runtime"),
            stability="experimental",
            notes=(
                "pattern-pool equivalence substitution",
                "size-preserving substitutions only",
            ),
        )

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply size-preserving pattern substitutions across the binary."""
        self._reset_random()
        self._ensure_analyzed(binary)

        arch_family, bits = binary.get_arch_family()
        if arch_family != "x86" or bits != ARCH_BITS_64:
            logger.warning(f"Pattern substitution supports x86_64 only, got: {arch_family}/{bits}")
            return {"mutations_applied": 0, "skipped": True, "reason": "unsupported architecture"}

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        logger.info(f"Pattern substitution: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            func_addr = func.get("offset", func.get("addr", 0))
            try:
                instructions = binary.get_function_disasm(func_addr)
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            if not instructions:
                continue

            func_mutations = self._mutate_function(binary, func_addr, instructions)
            mutations_applied += func_mutations
            if func_mutations:
                functions_mutated += 1

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
        }

    def _mutate_function(self, binary: Any, func_addr: int, instructions: list[dict[str, Any]]) -> int:
        """Apply size-preserving substitutions within a single function."""
        applied = 0
        for edit in self._integration.enumerate_substitutions(instructions):
            if edit["length"] != 1:
                continue
            if applied >= self.max_substitutions:
                break
            if random.random() > self.probability:
                continue

            idx = edit["index"]
            if idx >= len(instructions):
                continue
            if self._apply_edit(binary, func_addr, instructions[idx], edit):
                applied += 1
        return applied

    def _apply_edit(
        self,
        binary: Any,
        func_addr: int,
        original: dict[str, Any],
        edit: dict[str, Any],
    ) -> bool:
        """Assemble and write one size-preserving substitution. Returns True on success."""
        addr = original.get("addr", 0)
        orig_size = original.get("size", 0)
        if addr == 0 or orig_size == 0:
            return False

        assembled = self._assemble_replacement(binary, func_addr, edit["replacement"])
        # Larger replacements need cave/relocation support (out of scope here).
        if not assembled or len(assembled) > orig_size:
            return False

        # Preserve layout by padding the freed tail with single-byte NOPs (x86_64).
        new_bytes = assembled + b"\x90" * (orig_size - len(assembled))

        original_bytes = binary.read_bytes(addr, orig_size)
        if new_bytes == original_bytes:
            return False

        mutation_checkpoint = self._create_mutation_checkpoint("pattern_subst")

        if not binary.write_bytes(addr, new_bytes):
            return False

        mutated_bytes = binary.read_bytes(addr, orig_size)
        replacement_disasm = "; ".join(ins.opcode for ins in edit["replacement"])
        record = self._record_mutation(
            function_address=func_addr,
            start_address=addr,
            end_address=addr + orig_size - 1,
            original_bytes=original_bytes,
            mutated_bytes=mutated_bytes,
            original_disasm=original.get("disasm", ""),
            mutated_disasm=replacement_disasm,
            mutation_kind="pattern_substitution",
            metadata={"pattern_pool": edit["pool"]},
        )

        if self._validate_mutation_or_rollback(binary, record, mutation_checkpoint):
            return False

        logger.info(f"Pattern-substituted '{original.get('disasm')}' with '{replacement_disasm}' at 0x{addr:x}")
        return True

    def _assemble_replacement(self, binary: Any, func_addr: int, replacement: list[Any]) -> bytes | None:
        """Assemble a generated instruction sequence to bytes, or None on failure."""
        all_bytes = b""
        for ins in replacement:
            asm = ins.opcode.strip()
            if not asm:
                return None
            inst_bytes = binary.assemble(asm, func_addr)
            if not inst_bytes:
                logger.debug(f"Failed to assemble replacement part: {asm}")
                return None
            all_bytes += inst_bytes
        return all_bytes
