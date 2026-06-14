"""
Constant unfolding mutation pass.

Unfolds constant expressions into equivalent instructions,
increasing code complexity while preserving semantics.

Examples:
    add eax, 10  ->  inc eax; inc eax; ... (10 times)
    mov eax, 0   ->  xor eax, eax
    mov eax, 1   ->  xor eax, eax; inc eax
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.mutations.base import MutationPass
from r2morph.mutations.constant_unfolding_helpers import (
    apply_single_unfold,
    calculate_sequence_size,
    get_reg_mapping,
    match_unfold_pattern,
    select_candidates,
    unfold_constant_add,
    unfold_constant_sub,
    unfold_one,
    unfold_zero,
)

logger = logging.getLogger(__name__)


class ConstantUnfoldingPass(MutationPass):
    """
    Mutation pass that unfolds constant expressions.

    This pass finds instructions with immediate constants and transforms
    them into equivalent sequences of instructions, making static analysis
    more difficult.

    Unfolding patterns:
    - mov reg, 0 -> xor reg, reg
    - mov reg, 1 -> xor reg, reg; inc reg
    - add reg, N -> multiple inc/add with smaller values
    - push N -> mov reg, N; push reg

    Config options:
        - probability: Probability of unfolding a constant (default: 0.3)
        - max_unfolds_per_function: Max unfolds per function (default: 5)
        - max_sequence_length: Max instructions in unfolded sequence (default: 10)
        - size_limit: Max size increase factor (default: 3.0)
    """

    UNFOLDING_PATTERNS = {
        "zero": {
            "patterns": [
                "xor {reg}, {reg}",
                "sub {reg}, {reg}",
                "and {reg}, 0",
            ],
            "description": "Ways to zero a register",
        },
        "one": {
            "in_x86_64": [
                "xor {reg}, {reg}; inc {reg}",
                "or {reg}, 1",
            ],
            "in_x86": [
                "xor {reg}, {reg}; inc {reg}",
                "or {reg}, 1",
            ],
            "description": "Ways to set register to 1",
        },
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="ConstantUnfolding", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_unfolds = self.config.get("max_unfolds_per_function", 5)
        self.max_sequence = self.config.get("max_sequence_length", 10)
        self.size_limit = self.config.get("size_limit", 3.0)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64", "x86", "arm64"),
            validators=("structural", "runtime"),
            stability="experimental",
            notes=(
                "unfolds constants into sequences",
                "may increase code size",
                "preserves register semantics",
            ),
        )

    def _get_reg_mapping(self, bits: int) -> dict[str, list[str]]:
        return get_reg_mapping(bits)

    def _unfold_zero(self, reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
        return unfold_zero(reg, bits, binary, base_addr)

    def _unfold_one(self, reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
        """
        Unfold setting register to one.

        Args:
            reg: Register name
            bits: Architecture bits
            binary: Any instance
            base_addr: Base address

        Returns:
            List of instruction strings
        """

        return unfold_one(reg, bits, binary, base_addr)

    def _unfold_constant_add(self, reg: str, value: int, bits: int) -> list[str] | None:
        """
        Unfold add reg, value into multiple operations.

        Args:
            reg: Register name
            value: Constant value to add
            bits: Architecture bits

        Returns:
            List of instruction strings or None
        """
        return unfold_constant_add(reg, value, bits, self.max_sequence)

    def _unfold_constant_sub(self, reg: str, value: int, bits: int) -> list[str] | None:
        """
        Unfold sub reg, value into multiple operations.

        Args:
            reg: Register name
            value: Constant value to subtract
            bits: Architecture bits

        Returns:
            List of instruction strings or None
        """
        return unfold_constant_sub(reg, value, bits, self.max_sequence)

    def _calculate_sequence_size(self, instructions: list[str], binary: Any, base_addr: int) -> int:
        """
        Calculate total size of instruction sequence.

        Args:
            instructions: List of instruction strings
            binary: Any instance
            base_addr: Base address for assembly

        Returns:
            Total size in bytes
        """
        return calculate_sequence_size(instructions, binary, base_addr)

    def _select_candidates(self, binary: Any, functions: list[dict[str, Any]]) -> list[tuple[dict, list]]:
        """
        Iterate functions, get disasm, and filter candidate instructions.

        Args:
            binary: Any instance
            functions: List of function dicts

        Returns:
            List of (func, selected_candidates) tuples
        """
        return select_candidates(binary, functions, self.max_unfolds)

    def _match_unfold_pattern(
        self,
        disasm: str,
        bits: int,
        binary: Any,
        func_addr: int,
    ) -> tuple[list[str] | None, bool]:
        """Match instruction to an unfold pattern. Returns (unfolded_instructions, is_constant)."""
        return match_unfold_pattern(disasm, bits, binary, func_addr, self.max_sequence)

    def _apply_single_unfold(
        self,
        binary: Any,
        func: dict,
        addr: int,
        orig_size: int,
        disasm: str,
        unfolded: list[str],
        baseline: dict,
    ) -> bool:
        """Assemble, write, validate, and record a single unfold. Returns True on success."""
        return apply_single_unfold(self, binary, func, addr, orig_size, disasm, unfolded, baseline)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply constant unfolding to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 64)

        if arch not in ["x86", "x86_64"]:
            logger.warning(f"Constant unfolding only supports x86 architectures, got: {arch}")
            return {"mutations_applied": 0, "skipped": True, "reason": "unsupported architecture"}

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        constants_unfolded = 0
        size_increase = 0

        logger.info(f"Constant unfolding: processing {len(functions)} functions")

        for func, selected in self._select_candidates(binary, functions):
            func_mutations = 0

            for insn in selected:
                if random.random() > self.probability:
                    continue

                if func_mutations >= self.max_unfolds:
                    break

                disasm = insn.get("disasm", "").lower()
                addr = insn.get("addr", 0)
                orig_size = insn.get("size", 0)

                if addr == 0 or orig_size == 0:
                    continue

                try:
                    unfolded, is_constant = self._match_unfold_pattern(disasm, bits, binary, func["addr"])
                    if not unfolded:
                        continue
                    if is_constant:
                        constants_unfolded += 1

                    new_size = self._calculate_sequence_size(unfolded, binary, func["addr"])
                    if new_size == 0:
                        continue
                    if new_size > orig_size:
                        if self.size_limit > 1 and new_size > orig_size * self.size_limit:
                            continue
                        if new_size > orig_size + 16:
                            continue

                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                    if self._apply_single_unfold(binary, func, addr, orig_size, disasm, unfolded, baseline):
                        logger.info(f"Unfolded constant: '{disasm}' -> '{'; '.join(unfolded)}' at 0x{addr:x}")
                        func_mutations += 1
                        mutations_applied += 1
                        size_increase += new_size - orig_size

                except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                    logger.debug(f"Failed to unfold constant at 0x{addr:x}: {e}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(
            f"Constant unfolding complete: {mutations_applied} unfoldings in "
            f"{functions_mutated} functions, size change: {size_increase:+d} bytes"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "constants_unfolded": constants_unfolded,
            "total_functions": len(functions),
            "size_increase": size_increase,
            "max_sequence_length": self.max_sequence,
            "size_limit": self.size_limit,
        }
