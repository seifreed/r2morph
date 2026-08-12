"""
Instruction substitution mutation pass.

Replaces instructions with semantically equivalent alternatives.
Implements r2morph-style bidirectional equivalences and advanced patterns.

Features:
- Bidirectional equivalence groups
- Flag preservation with pushfd/popfd
- Force different mode
- Strict size validation
- jmp + dead code patterns (dynamically generated)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import ARCH_BITS_64
from r2morph.mutations.base import MutationPass
from r2morph.mutations.instruction_substitution_arm64 import apply_arm64_mov_substitution
from r2morph.mutations.instruction_substitution_helpers import (
    equivalent_flags_written,
    get_equivalents,
    init_substitution_rules,
    instruction_flags_written,
    select_candidates,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _SubstitutionChoice:
    original_pattern: str
    equivalents: tuple[str, ...]
    group_index: int | None
    replacement: str
    arch_family: str


class InstructionSubstitutionPass(MutationPass):
    """
    Mutation pass that substitutes instructions with equivalent ones.

    Replaces instructions with semantically equivalent alternatives to
    change the binary signature while preserving behavior.

    Implements r2morph-style features:
    - Bidirectional equivalences (any pattern can match and be replaced by any other)
    - Jump-based dead code patterns
    - Flag preservation with pushfd/popfd
    - Strict size validation mode
    - Force different mode

    Config options:
        - max_substitutions_per_function: Maximum substitutions per function
        - probability: Probability of substituting a candidate instruction
        - force_different: Force mutations to be different from original (r2morph-style)
        - strict_size: Only apply mutations if size matches exactly (no NOP padding)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize instruction substitution pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="InstructionSubstitution", config=config)
        self.max_substitutions = self.config.get("max_substitutions_per_function", 10)
        self.probability = self.config.get("probability", 0.7)
        self.force_different = self.config.get("force_different", False)
        self.strict_size = self.config.get("strict_size", False)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64", "arm", "arm64"),
            validators=("structural", "runtime", "symbolic"),
            stability="stable",
            notes=("known equivalence groups", "bounded symbolic observables"),
            validator_capabilities={
                "structural": {
                    "mode": "region",
                    "coverage": "patch integrity + invariant checks",
                },
                "runtime": {
                    "mode": "per-pass + final",
                    "coverage": "sample-based equivalence",
                },
                "symbolic": {
                    "mode": "experimental",
                    "scope": "bounded real-binary and shellcode observables",
                    "confidence": "best among stable passes",
                    "expected_statuses": (
                        "real-binary-observables-match",
                        "real-binary-observable-mismatch",
                        "bounded-step-observables-match",
                        "bounded-step-observable-mismatch",
                    ),
                },
            },
        )

        self._init_substitution_rules()

    def _init_substitution_rules(self) -> None:
        self.equivalence_groups, self.pattern_to_group = init_substitution_rules()

    def _get_equivalents(self, instruction: dict[str, Any], arch: str) -> tuple[str, list[str], int | None]:
        """
        Get all equivalent patterns for an instruction.

        Args:
            instruction: Instruction dictionary from r2
            arch: Architecture (x86, arm, etc.)

        Returns:
            Tuple of (original_pattern, list of equivalent patterns)
        """
        return get_equivalents(instruction, arch, self.pattern_to_group, self.equivalence_groups)

    def _select_candidates(
        self, binary: Any, functions: list[dict[str, Any]], arch_family: str
    ) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
        """
        Iterate functions, get disasm, and filter candidate instructions for substitution.

        Args:
            binary: Any instance
            functions: List of function dicts
            arch_family: Architecture family string

        Returns:
            List of (func, candidate_instructions) tuples
        """
        return select_candidates(binary, functions, arch_family, self.pattern_to_group, self.equivalence_groups)

    @staticmethod
    def _flag_safe_equivalents(instruction: dict[str, Any], arch_family: str, equivalents: list[str]) -> list[str]:
        if arch_family != "x86" or not instruction.get("flags_live_after", True):
            return equivalents
        original_flags = instruction_flags_written(instruction.get("disasm", ""))
        return [equivalent for equivalent in equivalents if equivalent_flags_written(equivalent) == original_flags]

    def _choose_equivalent(self, original_pattern: str, equivalents: list[str], mutation_count: int) -> str | None:
        if random.random() >= self.probability or mutation_count >= self.max_substitutions:
            return None
        available = [equivalent for equivalent in equivalents if equivalent != original_pattern]
        if self.force_different:
            return random.choice(available) if available else None
        chosen = random.choice(equivalents)
        return chosen if chosen != original_pattern else None

    @staticmethod
    def _assemble_equivalent(binary: Any, function_address: int, replacement: str) -> bytes | None:
        if ";" not in replacement:
            assembled = binary.assemble(replacement, function_address)
            return assembled if isinstance(assembled, bytes) else None
        assembled = b""
        for instruction in replacement.split(";"):
            instruction_bytes = binary.assemble(instruction.strip(), function_address)
            if not isinstance(instruction_bytes, bytes) or not instruction_bytes:
                logger.debug(f"Failed to assemble part: {instruction.strip()}")
                return None
            assembled += instruction_bytes
        return assembled

    def _validate_substitution(self, binary: Any, record: Any, checkpoint: Any) -> bool:
        if self._validation_manager is None:
            return True
        outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
        if outcome.passed or checkpoint is None or self._session is None:
            return True
        self._rollback_mutation(binary, checkpoint)
        return False

    def _apply_equivalent(
        self,
        binary: Any,
        function: dict[str, Any],
        instruction: dict[str, Any],
        choice: _SubstitutionChoice,
    ) -> bool:
        address = instruction.get("addr", 0)
        original_size = instruction.get("size", 0)
        checkpoint = self._create_mutation_checkpoint("subst")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        original_bytes = binary.read_bytes(address, original_size)
        new_bytes = self._assemble_equivalent(binary, function["addr"], choice.replacement)
        if not new_bytes:
            return False
        new_size = len(new_bytes)
        use_padding = new_size < original_size and not self.strict_size
        if new_size != original_size and not use_padding:
            logger.debug(
                f"Skipping substitution: size mismatch ({new_size} vs {original_size}, strict={self.strict_size})"
            )
            return False
        if not binary.write_bytes(address, new_bytes):
            return False
        if use_padding and not binary.nop_fill(address + new_size, original_size - new_size):
            self._rollback_uncommitted(
                binary,
                checkpoint,
                reason="Instruction-substitution NOP fill failed; aborting (fail-fast)",
            )
            return False
        mutated_disasm = f"{choice.replacement}; nop_fill" if use_padding else choice.replacement
        metadata = {
            "strict_size": self.strict_size,
            "equivalence_arch": choice.arch_family,
            "equivalence_group_index": choice.group_index,
            "equivalence_group_size": len(choice.equivalents),
            "equivalence_original_pattern": choice.original_pattern,
            "equivalence_replacement_pattern": choice.replacement,
            "equivalence_members": list(choice.equivalents),
            "structural_baseline": baseline,
        }
        if use_padding:
            metadata["nop_fill_size"] = original_size - new_size
        record = self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + original_size - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(address, original_size),
            original_disasm=instruction.get("disasm", ""),
            mutated_disasm=mutated_disasm,
            mutation_kind="instruction_substitution",
            metadata=metadata,
        )
        if not self._validate_substitution(binary, record, checkpoint):
            return False
        suffix = " (+ NOPs)" if use_padding else ""
        logger.info(f"Substituted '{instruction.get('disasm')}' with '{choice.replacement}'{suffix} at 0x{address:x}")
        return True

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply instruction substitution mutations to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if self._reset_random() is not None:
            self._init_substitution_rules()

        self._ensure_analyzed(binary)

        arch_family, bits = binary.get_arch_family()

        if arch_family == "arm" and bits == ARCH_BITS_64:
            return self._apply_arm64_mov_substitution(binary)

        if arch_family not in self.equivalence_groups:
            logger.warning(f"No substitution rules for architecture: {arch_family}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch_family}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        candidates_found = 0

        logger.info(f"Instruction substitution: processing {len(functions)} functions")

        for func, func_candidates in self._select_candidates(binary, functions, arch_family):
            func_mutations = 0
            for insn in func_candidates:
                original_pattern, equivalents, group_idx = self._get_equivalents(insn, arch_family)
                if len(equivalents) <= 1:
                    continue
                candidates_found += 1
                equivalents = self._flag_safe_equivalents(insn, arch_family, equivalents)
                if len(equivalents) <= 1:
                    continue
                chosen = self._choose_equivalent(original_pattern, equivalents, func_mutations)
                address = insn.get("addr", 0)
                if chosen is None or address == 0 or insn.get("size", 0) == 0:
                    continue
                choice = _SubstitutionChoice(
                    original_pattern,
                    tuple(equivalents),
                    group_idx,
                    chosen,
                    arch_family,
                )
                try:
                    if not self._apply_equivalent(binary, func, insn, choice):
                        continue
                    func_mutations += 1
                    mutations_applied += 1
                    self._init_substitution_rules()
                except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
                    logger.error(f"Failed to substitute at 0x{address:x}: {error}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(
            f"Instruction substitution complete: {mutations_applied} substitutions "
            f"in {functions_mutated} functions ({candidates_found} candidates found)"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "candidates_found": candidates_found,
            "total_functions": len(functions),
            "force_different": self.force_different,
            "strict_size": self.strict_size,
        }

    def _apply_arm64_mov_substitution(self, binary: Any) -> dict[str, Any]:
        return apply_arm64_mov_substitution(binary, self.max_substitutions)
