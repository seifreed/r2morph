"""
Data flow-aware mutation pass.

Uses liveness and reaching definition analysis to perform safer mutations
by understanding register and value flow through basic blocks.
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.data_flow_mutation_helpers import (
    SAFE_INSTRUCTIONS as DATA_FLOW_SAFE_INSTRUCTIONS,
)
from r2morph.mutations.data_flow_mutation_helpers import (
    analyze_function_liveness,
    find_safe_substitution_candidates,
    is_register_safe_to_use,
)

logger = logging.getLogger(__name__)


class DataFlowMutationPass(MutationPass):
    """
    Mutation pass that uses data flow analysis for safer transformations.

    This pass analyzes register liveness and reaching definitions to:
    - Identify dead registers (safe to mutate)
    - Find safe substitution opportunities
    - Avoid mutating critical values in transit

    Config options:
        - probability: Probability of applying mutation (default: 0.3)
        - max_mutations_per_function: Max mutations per function (default: 5)
        - use_liveness: Enable liveness-based optimization (default: True)
        - use_reaching_defs: Enable reaching definition analysis (default: True)
    """

    SAFE_INSTRUCTIONS = DATA_FLOW_SAFE_INSTRUCTIONS

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="DataFlowMutation", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_mutations = self.config.get("max_mutations_per_function", 5)
        self.use_liveness = self.config.get("use_liveness", True)
        self.use_reaching_defs = self.config.get("use_reaching_defs", True)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural", "runtime"),
            stability="experimental",
            notes=(
                "requires cfg analysis",
                "uses liveness analysis for safety",
                "avoids mutating live registers",
            ),
        )

    def _analyze_function_liveness(self, instructions: list[dict[str, Any]]) -> dict[int, set[str]]:
        return analyze_function_liveness(instructions)

    def _is_register_safe_to_use(
        self,
        reg: str,
        addr: int,
        live_in: dict[int, set[str]],
        caller_saved: set[str],
    ) -> bool:
        return is_register_safe_to_use(reg, addr, live_in, caller_saved)

    def _find_safe_substitution_candidates(
        self,
        instructions: list[dict[str, Any]],
        live_in: dict[int, set[str]],
        arch: str,
    ) -> list[tuple[dict[str, Any], str, str]]:
        return find_safe_substitution_candidates(instructions, live_in, arch)

    def _analyze_candidates(
        self, binary: Any, function: dict[str, Any], arch: str
    ) -> list[tuple[dict[str, Any], str, str]] | None:
        try:
            instructions = binary.get_function_disasm(function["addr"])
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
            logger.debug(f"Failed to get disasm for {function.get('name')}: {error}")
            return None
        live_in = self._analyze_function_liveness(instructions) if self.use_liveness else {}
        return self._find_safe_substitution_candidates(instructions, live_in, arch)

    def _apply_substitution(
        self,
        binary: Any,
        function: dict[str, Any],
        instruction: dict[str, Any],
        original_register: str,
        substitute_register: str,
    ) -> bool:
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        disasm = instruction.get("disasm", "")
        checkpoint = self._create_mutation_checkpoint("df")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        original_bytes = binary.read_bytes(address, size)
        replacement = disasm.lower().replace(original_register.lower(), substitute_register.lower())
        new_bytes = binary.assemble(replacement, function["addr"])
        if not new_bytes or len(new_bytes) > size or not binary.write_bytes(address, new_bytes):
            return False
        if len(new_bytes) < size and not binary.nop_fill(address + len(new_bytes), size - len(new_bytes)):
            logger.warning(
                "NOP fill failed at 0x%x after data-flow substitution; rolling back", address + len(new_bytes)
            )
            self._rollback_uncommitted(
                binary,
                checkpoint,
                reason="data_flow_mutation NOP fill failed; aborting (fail-fast)",
            )
            return False
        record = self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(address, size),
            original_disasm=disasm,
            mutated_disasm=replacement,
            mutation_kind="data_flow_substitution",
            metadata={
                "original_register": original_register,
                "substitute_register": substitute_register,
                "liveness_guided": self.use_liveness,
                "structural_baseline": baseline,
            },
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return False
        logger.info(f"Data flow: substituted {original_register} -> {substitute_register} at 0x{address:x}")
        return True

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply data flow-aware mutations to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        self._ensure_analyzed(binary)

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")
        arch_info.get("bits", 64)

        if arch not in ["x86", "x86_64"]:
            logger.warning(f"Data flow mutation only supports x86 architectures, got: {arch}")
            return {"mutations_applied": 0, "skipped": True, "reason": "unsupported architecture"}

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        liveness_used = 0

        logger.info(f"Data flow mutation: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            candidates = self._analyze_candidates(binary, func, arch)
            if candidates is None:
                continue
            liveness_used += int(self.use_liveness)
            if not candidates:
                continue

            func_mutations = 0
            selected = random.sample(candidates, min(self.max_mutations, len(candidates)))

            for insn, orig_reg, subst_reg in selected:
                if random.random() > self.probability:
                    continue

                if func_mutations >= self.max_mutations:
                    break

                address = insn.get("addr", 0)
                if address == 0 or insn.get("size", 0) == 0:
                    continue
                try:
                    if not self._apply_substitution(binary, func, insn, orig_reg, subst_reg):
                        continue
                    func_mutations += 1
                    mutations_applied += 1
                except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
                    logger.debug(f"Failed data flow mutation at 0x{address:x}: {error}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(
            f"Data flow mutation complete: {mutations_applied} mutations in "
            f"{functions_mutated} functions (liveness: {liveness_used})"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
            "liveness_analysis_used": liveness_used,
            "dead_registers_found": mutations_applied,
            "use_liveness": self.use_liveness,
            "use_reaching_defs": self.use_reaching_defs,
        }
