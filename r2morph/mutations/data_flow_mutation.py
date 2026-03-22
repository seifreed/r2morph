"""
Data flow-aware mutation pass.

Uses liveness and reaching definition analysis to perform safer mutations
by understanding register and value flow through basic blocks.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

if TYPE_CHECKING:
    pass
from r2morph.mutations.base import MutationPass

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

    SAFE_INSTRUCTIONS = {
        "nop",
        "mov",
        "xor",
        "and",
        "or",
        "add",
        "sub",
        "shl",
        "shr",
        "not",
        "neg",
        "inc",
        "dec",
        "push",
        "pop",
        "lea",
        "test",
        "cmp",
    }

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
        """
        Perform simple backward liveness analysis.

        Args:
            instructions: List of instructions with disasm

        Returns:
            Dict mapping instruction addresses to live register sets
        """
        live_in: dict[int, set[str]] = {}
        live_out: dict[int, set[str]] = {}

        x86_regs = {
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
        }

        for insn in reversed(instructions):
            addr = insn.get("addr", 0)
            disasm = insn.get("disasm", "").lower()

            used = set()
            defined = set()

            if "call" in disasm:
                used.update(["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"])
                defined.add("rax")

            parts = disasm.replace(",", " ").replace("[", " [ ").replace("]", " ] ").split()

            for i, part in enumerate(parts):
                if part in x86_regs:
                    if i > 0 and parts[i - 1] in (
                        "mov",
                        "lea",
                        "xor",
                        "and",
                        "or",
                        "add",
                        "sub",
                        "shl",
                        "shr",
                        "not",
                        "neg",
                    ):
                        defined.add(part)
                    else:
                        used.add(part)

            next_addr = insn.get("next_addr", 0)
            succ_live = live_in.get(next_addr, set()) if next_addr else set()

            live_out[addr] = succ_live.copy()
            live_in[addr] = (used | (succ_live - defined)) & x86_regs

        return live_in

    def _get_dead_registers(self, addr: int, live_in: dict[int, set[str]], all_regs: set[str]) -> set[str]:
        """
        Get registers that are dead at a given address.

        Args:
            addr: Instruction address
            live_in: Liveness information
            all_regs: All registers under consideration

        Returns:
            Set of dead registers
        """
        live = live_in.get(addr, set())
        return all_regs - live

    def _is_register_safe_to_use(
        self,
        reg: str,
        addr: int,
        live_in: dict[int, set[str]],
        caller_saved: set[str],
    ) -> bool:
        """
        Check if a register is safe to use at a given address.

        A register is safe to use if:
        1. It's caller-saved (scratch)
        2. It's not live at this point

        Args:
            reg: Register name
            addr: Instruction address
            live_in: Liveness information
            caller_saved: Set of caller-saved registers

        Returns:
            True if register is safe to use
        """
        if reg not in caller_saved:
            return False

        live = live_in.get(addr, set())
        return reg not in live

    def _find_safe_substitution_candidates(
        self,
        instructions: list[dict[str, Any]],
        live_in: dict[int, set[str]],
        arch: str,
    ) -> list[tuple[dict[str, Any], str, str]]:
        """
        Find instructions where register substitution is safe.

        Args:
            instructions: List of instructions
            live_in: Liveness analysis results
            arch: Architecture

        Returns:
            List of (instruction, original_reg, substitute_reg) tuples
        """
        candidates = []

        caller_saved_64 = {
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
        }
        caller_saved_32 = {"eax", "ecx", "edx"}

        caller_saved = caller_saved_64 if arch == "x86_64" else caller_saved_32
        all_regs = caller_saved.copy()

        for insn in instructions:
            addr = insn.get("addr", 0)
            disasm = insn.get("disasm", "").lower()

            mnemonic = disasm.split()[0] if disasm else ""
            if mnemonic not in self.SAFE_INSTRUCTIONS:
                continue

            dead_regs = self._get_dead_registers(addr, live_in, all_regs)
            if not dead_regs:
                continue

            for reg in caller_saved:
                if reg in disasm and reg in live_in.get(addr, set()):
                    for dead_reg in dead_regs:
                        candidates.append((insn, reg, dead_reg))
                        break

        return candidates

    def _generate_dead_code_with_liveness(self, dead_regs: set[str], bits: int, size: int) -> list[str] | None:
        """
        Generate dead code that uses dead registers.

        Args:
            dead_regs: Set of dead registers
            bits: Architecture bits (32 or 64)
            size: Target size in bytes

        Returns:
            List of instructions or None
        """
        if not dead_regs:
            return None

        reg = random.choice(list(dead_regs))

        if bits == 64:
            patterns = [
                [f"push {reg}", f"mov {reg}, 0", f"xor {reg}, {reg}", f"pop {reg}"],
                [f"push {reg}", f"add {reg}, 1", f"sub {reg}, 1", f"pop {reg}"],
                [f"xor {reg}, {reg}", f"not {reg}", f"not {reg}"],
            ]
        else:
            patterns = [
                [f"push {reg}", f"mov {reg}, 0", f"pop {reg}"],
                [f"xor {reg}, {reg}"],
            ]

        return random.choice(patterns)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply data flow-aware mutations to the binary.

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

                        if len(new_bytes) < size:
                            binary.nop_fill(addr + len(new_bytes), size - len(new_bytes))

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
                        if self._validation_manager is not None:
                            outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
                            if not outcome.passed and mutation_checkpoint is not None:
                                if self._session is not None:
                                    self._session.rollback_to(mutation_checkpoint)
                                binary.reload()
                                if self._records:
                                    self._records.pop()
                                if self._rollback_policy == "fail-fast":
                                    raise RuntimeError("Mutation-level validation failed")
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
