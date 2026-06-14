"""
Data flow-aware mutation pass.

Uses liveness and reaching definition analysis to perform safer mutations
by understanding register and value flow through basic blocks.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.data_flow_mutation_helpers import (
    SAFE_INSTRUCTIONS as DATA_FLOW_SAFE_INSTRUCTIONS,
)
from r2morph.mutations.data_flow_mutation_helpers import (
    analyze_function_liveness,
    find_safe_substitution_candidates,
    generate_dead_code_with_liveness,
    get_dead_registers,
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

    def _get_dead_registers(self, addr: int, live_in: dict[int, set[str]], all_regs: set[str]) -> set[str]:
        return get_dead_registers(addr, live_in, all_regs)

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

    def _generate_dead_code_with_liveness(self, dead_regs: set[str], bits: int, size: int) -> list[str] | None:
        return generate_dead_code_with_liveness(dead_regs, bits, size)

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
        dead_regs_found = 0

        logger.info(f"Data flow mutation: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            if self.use_liveness:
                live_in = self._analyze_function_liveness(instructions)
                liveness_used += 1
            else:
                live_in = {}

            candidates = self._find_safe_substitution_candidates(instructions, live_in, arch)

            if not candidates:
                continue

            func_mutations = 0
            selected = random.sample(candidates, min(self.max_mutations, len(candidates)))

            for insn, orig_reg, subst_reg in selected:
                if random.random() > self.probability:
                    continue

                if func_mutations >= self.max_mutations:
                    break

                addr = insn.get("addr", 0)
                size = insn.get("size", 0)
                disasm = insn.get("disasm", "")

                if addr == 0 or size == 0:
                    continue

                try:
                    mutation_checkpoint = self._create_mutation_checkpoint("df")
                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])
                    original_bytes = binary.read_bytes(addr, size)

                    new_disasm = disasm.lower().replace(orig_reg.lower(), subst_reg.lower())
                    new_bytes = binary.assemble(new_disasm, func["addr"])

                    if new_bytes and len(new_bytes) <= size:
                        if not binary.write_bytes(addr, new_bytes):
                            continue

                        if len(new_bytes) < size and not binary.nop_fill(addr + len(new_bytes), size - len(new_bytes)):
                            # Shorter replacement written but trailing gap
                            # not NOP-filled -> stale tail of the original
                            # instruction remains. nop_fill's bool was
                            # ignored and the patch recorded as success.
                            # Roll back like the validation-failure path.
                            logger.warning(
                                "NOP fill failed at 0x%x after data-flow substitution; rolling back",
                                addr + len(new_bytes),
                            )
                            if self._session is not None and mutation_checkpoint is not None:
                                self._session.rollback_to(mutation_checkpoint)
                            binary.reload()
                            if self._rollback_policy == "fail-fast":
                                raise RuntimeError("data_flow_mutation NOP fill failed; aborting (fail-fast)")
                            continue

                        mutated_bytes = binary.read_bytes(addr, size)
                        record = self._record_mutation(
                            function_address=func["addr"],
                            start_address=addr,
                            end_address=addr + size - 1,
                            original_bytes=original_bytes,
                            mutated_bytes=mutated_bytes,
                            original_disasm=disasm,
                            mutated_disasm=new_disasm,
                            mutation_kind="data_flow_substitution",
                            metadata={
                                "original_register": orig_reg,
                                "substitute_register": subst_reg,
                                "liveness_guided": self.use_liveness,
                                "structural_baseline": baseline,
                            },
                        )
                        if self._validate_mutation_or_rollback(binary, record, mutation_checkpoint):
                            continue

                        logger.info(f"Data flow: substituted {orig_reg} -> {subst_reg} at 0x{addr:x}")
                        func_mutations += 1
                        mutations_applied += 1
                        dead_regs_found += 1

                except Exception as e:
                    logger.debug(f"Failed data flow mutation at 0x{addr:x}: {e}")

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
            "dead_registers_found": dead_regs_found,
            "use_liveness": self.use_liveness,
            "use_reaching_defs": self.use_reaching_defs,
        }
