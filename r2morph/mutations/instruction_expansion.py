"""
Instruction expansion mutation pass.

Expands single instructions into multiple equivalent instructions.
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass
from r2morph.mutations.instruction_expansion_helpers import (
    EXPANSION_RULES as INSTRUCTION_EXPANSION_RULES,
)
from r2morph.mutations.instruction_expansion_helpers import (
    build_instruction_from_pattern,
    get_expansion_size_increase,
    is_safe_to_expand,
    match_expansion_pattern,
)

logger = logging.getLogger(__name__)

_MIN_EXPANDABLE_FUNCTION_SIZE_BYTES = 20


class InstructionExpansionPass(MutationPass):
    """
    Mutation pass that expands instructions into equivalent sequences.

    This mutation replaces single instructions with multiple instructions
    that perform the same operation, increasing code size and complexity.

    Examples (x86/x64):
        mov eax, 5    ->    xor eax, eax
                            add eax, 5

        inc eax       ->    add eax, 1

        dec eax       ->    sub eax, 1

        neg eax       ->    not eax
                            inc eax

        shl eax, 1    ->    add eax, eax

        imul eax, 3   ->    mov ebx, eax
                            shl eax, 1
                            add eax, ebx

    Config options:
        - probability: Probability of expanding an instruction (default: 0.2)
        - max_expansions_per_function: Max expansions per function (default: 5)
        - max_expansion_size: Max instruction sequence length (default: 4)
    """

    # Only single-instruction expansions are supported. Multi-instruction
    # expansions (e.g., imul reg,3 -> mov tmp,reg; shl reg,1; add reg,tmp)
    # require temporary register allocation and are not yet implemented.
    #
    # FLAG SAFETY NOTE:
    # - inc/dec → add/sub: UNSAFE if CF is live (inc/dec preserve CF, add/sub modify it)
    # - mov reg, 0 → xor/sub: UNSAFE if ANY flags are live (mov doesn't touch flags)
    # These rules are EXCLUDED to avoid semantic corruption. Only flag-safe
    # expansions are included.
    EXPANSION_RULES = INSTRUCTION_EXPANSION_RULES

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize instruction expansion pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="InstructionExpansion", config=config)
        self.probability = self.config.get("probability", 0.2)
        self.max_expansions = self.config.get("max_expansions_per_function", 5)
        self.max_expansion_size = self.config.get("max_expansion_size", 4)

    def configure_for_memory_constraints(self, factor: float) -> None:
        """Reduce expansion count for memory-efficient mode."""
        original = self.max_expansions
        self.max_expansions = max(1, int(self.max_expansions * factor))
        self.config["max_expansions_per_function"] = self.max_expansions
        if self.max_expansions != original:
            logging.getLogger(__name__).debug(
                f"Memory-efficient: reduced max_expansions from {original} to {self.max_expansions}"
            )

    def _match_expansion_pattern(self, instruction: dict[str, Any], arch: str) -> list[list[tuple[str, ...]]]:
        return match_expansion_pattern(instruction, arch, self.EXPANSION_RULES)

    def _build_instruction_from_pattern(self, pattern: tuple[str, ...], orig_parts: list[str]) -> str | None:
        return build_instruction_from_pattern(pattern, orig_parts)

    def _get_expansion_size_increase(self, expansion: list[tuple[str, ...]]) -> int:
        return get_expansion_size_increase(expansion)

    def _is_safe_to_expand(self, instruction: dict[str, Any], function_size: int) -> bool:
        return is_safe_to_expand(instruction, function_size)

    @staticmethod
    def _get_instructions(binary: Any, function: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            instructions = binary.get_function_disasm(function["addr"])
            return [instruction for instruction in instructions if isinstance(instruction, dict)]
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
            logger.debug(f"Failed to get disasm for {function.get('name')}: {error}")
            return []

    def _choose_expansion(
        self, instruction: dict[str, Any], arch_family: str, function_size: int
    ) -> list[tuple[str, ...]] | None:
        if not self._is_safe_to_expand(instruction, function_size):
            return None
        expansions = self._match_expansion_pattern(instruction, arch_family)
        if not expansions or random.random() > self.probability:
            return None
        chosen = random.choice(expansions)
        return chosen if len(chosen) <= self.max_expansion_size else None

    def _apply_single_expansion(
        self,
        binary: Any,
        function: dict[str, Any],
        instruction: dict[str, Any],
        pattern: tuple[str, ...],
    ) -> int | None:
        address = int(instruction.get("addr", 0))
        original_size = int(instruction.get("size", 0))
        original_disasm = instruction.get("disasm", "")
        replacement = self._build_instruction_from_pattern(pattern, original_disasm.lower().split())
        if replacement is None:
            return None
        new_bytes = binary.assemble(replacement, function["addr"])
        if not new_bytes or len(new_bytes) > original_size:
            return None
        checkpoint = self._create_mutation_checkpoint("insn_expand")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        original_bytes = binary.read_bytes(address, original_size)
        if not binary.write_bytes(address, new_bytes):
            return None
        if len(new_bytes) < original_size and not binary.nop_fill(
            address + len(new_bytes), original_size - len(new_bytes)
        ):
            logger.warning("NOP fill failed at 0x%x after shorter expansion; rolling back", address + len(new_bytes))
            self._rollback_uncommitted(
                binary,
                checkpoint,
                reason="Instruction-expansion NOP fill failed; aborting (fail-fast)",
            )
            return None
        mutated_bytes = binary.read_bytes(address, original_size)
        record = self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + original_size - 1,
            original_bytes=original_bytes if original_bytes else b"",
            mutated_bytes=mutated_bytes if mutated_bytes else new_bytes,
            original_disasm=original_disasm,
            mutated_disasm=replacement,
            mutation_kind="instruction_expansion",
            metadata={"expansion_type": "single", "structural_baseline": baseline},
        )
        if self._validation_manager is not None:
            outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
            if not outcome.passed and checkpoint is not None:
                self._rollback_mutation(binary, checkpoint)
                return None
        logger.info(
            f"Expanded '{original_disasm}' -> '{replacement}' at 0x{address:x} "
            f"({original_size} -> {len(new_bytes)} bytes)"
        )
        return len(new_bytes) - original_size

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply instruction expansion mutations to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()
        self._ensure_analyzed(binary)

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")

        arch_family = "x86" if arch in ["x86", "x64"] else arch

        if arch_family not in self.EXPANSION_RULES:
            logger.warning(f"No expansion rules for architecture: {arch}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        total_expansions = 0
        size_increase = 0

        logger.info(f"Instruction expansion: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < _MIN_EXPANDABLE_FUNCTION_SIZE_BYTES:
                continue

            func_expansions = 0
            func_size_increase = 0

            for insn in self._get_instructions(binary, func):
                if func_expansions >= self.max_expansions:
                    break

                chosen_expansion = self._choose_expansion(insn, arch_family, func.get("size", 0))
                if chosen_expansion is None:
                    continue

                address = insn.get("addr", 0)
                if address == 0 or insn.get("size", 0) == 0:
                    continue

                if len(chosen_expansion) != 1:
                    logger.debug(
                        f"Skipping multi-instruction expansion at 0x{address:x} "
                        f"(not implemented: would require {len(chosen_expansion)} instructions)"
                    )
                    continue
                try:
                    size_increase_for_instruction = self._apply_single_expansion(
                        binary, func, insn, chosen_expansion[0]
                    )
                except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
                    logger.debug(f"Failed to expand at 0x{address:x}: {error}")
                    continue
                if size_increase_for_instruction is None:
                    continue
                func_expansions += 1
                func_size_increase += size_increase_for_instruction

            if func_expansions > 0:
                mutations_applied += func_expansions
                total_expansions += func_expansions
                size_increase += func_size_increase
                functions_mutated += 1

                logger.info(
                    f"Expanded {func_expansions} instructions in {func.get('name')} (+{func_size_increase} bytes)"
                )

        logger.info(
            f"Instruction expansion complete: {total_expansions} expansions "
            f"in {functions_mutated} functions (+{size_increase} bytes total)"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_expansions": total_expansions,
            "size_increase_bytes": size_increase,
            "total_functions": len(functions),
        }
