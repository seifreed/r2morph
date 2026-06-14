"""
Register substitution mutation pass.

Replaces registers with equivalent unused registers in code sequences.
"""

from __future__ import annotations

import logging
from typing import Any

from r2morph.mutations.base import MutationPass
from r2morph.mutations.register_substitution_helpers import (
    count_register_uses,
    find_substitution_candidates,
    get_register_class,
    is_safe_lea_substitution,
    is_safe_size_extension_substitution,
    select_candidates,
)

logger = logging.getLogger(__name__)


class RegisterSubstitutionPass(MutationPass):
    """
    Mutation pass that substitutes registers with equivalent ones.

    This mutation replaces registers throughout a code sequence with
    different but equivalent registers, preserving program semantics.

    Example (x86):
        mov eax, 5     ->    mov ecx, 5
        add eax, 3     ->    add ecx, 3
        ret            ->    mov eax, ecx
                             ret

    The key is to ensure the substitution is valid within the scope
    and restore original values when needed (e.g., for calling conventions).

    Config options:
        - probability: Probability of substituting in a function (default: 0.2)
        - max_substitutions_per_function: Max substitutions per function (default: 3)
        - respect_calling_convention: Respect ABI calling conventions (default: True)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize register substitution pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="RegisterSubstitution", config=config)
        self.probability = self.config.get("probability", 0.2)
        self.max_substitutions = self.config.get("max_substitutions_per_function", 3)
        self.respect_calling_convention = self.config.get("respect_calling_convention", True)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64", "arm64", "arm"),
            validators=("structural", "runtime", "symbolic"),
            stability="stable",
            notes=(
                "ABI-aware caller-saved substitution",
                "arm64: uses caller-saved registers x0-x17, x30",
            ),
            validator_capabilities={
                "structural": {
                    "mode": "region",
                    "coverage": "patch integrity + invariant checks",
                },
                "runtime": {
                    "mode": "per-pass + final",
                    "coverage": "sample-based equivalence",
                    "recommended": True,
                },
                "symbolic": {
                    "mode": "experimental",
                    "scope": "bounded real-binary observables on mutated instructions",
                    "confidence": "limited",
                    "recommended": False,
                    "known_limitations": (
                        "register substitutions may diverge under single-step observable checks",
                        "prefer structural + runtime for release decisions",
                    ),
                    "expected_statuses": (
                        "real-binary-observable-mismatch",
                        "bounded-step-passed",
                    ),
                },
            },
        )

    def _get_register_class(self, arch: str) -> dict[str, list[str]]:
        return get_register_class(arch)

    def _find_substitution_candidates(self, instructions: list[dict[str, Any]], arch: str) -> list[tuple[str, str]]:
        return find_substitution_candidates(instructions, arch)

    def _count_register_uses(self, instructions: list[dict[str, Any]], register: str) -> int:
        return count_register_uses(instructions, register)

    def _is_safe_size_extension_substitution(self, disasm: str, orig_reg: str, subst_reg: str) -> bool:
        return is_safe_size_extension_substitution(disasm, orig_reg, subst_reg)

    def _is_safe_lea_substitution(self, disasm: str, orig_reg: str, subst_reg: str) -> bool:
        return is_safe_lea_substitution(disasm, orig_reg, subst_reg)

    def _select_candidates(
        self,
        binary: Any,
        functions: list[dict[str, Any]],
        arch: str,
    ) -> list[tuple[dict, list[dict], list[tuple[str, str]]]]:
        return select_candidates(binary, functions, arch, self.probability, self.max_substitutions)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply register substitution mutations to the binary.

        Args:
            binary: Object satisfying BinaryAccessProtocol

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 0)

        arch_key = arch
        if arch == "arm" and bits == 64:
            arch_key = "arm64"

        register_classes = self._get_register_class(arch_key)
        if not register_classes:
            logger.warning(f"No register classes defined for architecture: {arch}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        total_registers_substituted = 0

        logger.info(f"Register substitution: processing {len(functions)} functions")

        for func, instructions, selected in self._select_candidates(binary, functions, arch):

            func_mutations = 0
            for orig_reg, subst_reg in selected:
                substituted_count = 0

                for insn in instructions:
                    disasm = insn.get("disasm", "").lower()

                    if orig_reg not in disasm:
                        continue

                    mnemonic = disasm.split()[0] if disasm else ""

                    # Category 1: ALWAYS SKIP - Hardware/semantic restrictions
                    # These cannot be safely substituted due to hardware constraints
                    always_skip_mnemonics = [
                        "xlat",  # Table lookup with implicit AL register
                        "movabs",  # 64-bit immediate/address - complex syntax issues
                        "cmovz",
                        "cmovnz",
                        "cmove",
                        "cmovne",  # Conditional moves
                        "setne",
                        "sete",
                        "setz",
                        "setnz",  # Set byte on condition
                        "lock",  # Atomic operations prefix
                        "xadd",  # Atomic exchange-and-add
                        "cmpxchg",  # Atomic compare-and-exchange
                    ]
                    if mnemonic in always_skip_mnemonics:
                        continue

                    # Category 2: VALIDATE FIRST - Can be resolved with proper checks
                    # movzx/movsx: Size-extension instructions with manual encoding fallback
                    if mnemonic in ["movzx", "movsx"]:
                        if not self._is_safe_size_extension_substitution(disasm, orig_reg, subst_reg):
                            continue

                    # LEA: Address calculation - only safe if substituting destination
                    if mnemonic == "lea":
                        if not self._is_safe_lea_substitution(disasm, orig_reg, subst_reg):
                            continue

                    # Skip instructions with memory addresses to avoid corrupting them
                    if "[" in disasm and "]" in disasm:
                        # Check if register is only in memory operand (skip these)
                        parts = disasm.split("[")
                        if len(parts) > 1:
                            mem_part = parts[1].split("]")[0]
                            # If register only appears in memory operand, skip
                            non_mem_part = parts[0] + (parts[1].split("]")[1] if "]" in parts[1] else "")
                            if orig_reg not in non_mem_part and orig_reg in mem_part:
                                continue

                    new_disasm = disasm.replace(orig_reg, subst_reg)

                    addr = insn.get("addr", 0)
                    orig_size = insn.get("size", 0)

                    if addr == 0 or orig_size == 0:
                        continue

                    try:
                        mutation_checkpoint = self._create_mutation_checkpoint("reg")
                        baseline = {}
                        if self._validation_manager is not None:
                            baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])
                        original_bytes = binary.read_bytes(addr, orig_size)
                        new_bytes = binary.assemble(new_disasm, func["addr"])

                        if new_bytes:
                            new_size = len(new_bytes)

                            if new_size <= orig_size:
                                if not binary.write_bytes(addr, new_bytes):
                                    continue

                                if new_size < orig_size:
                                    if not binary.nop_fill(addr + new_size, orig_size - new_size):
                                        continue

                                logger.debug(
                                    f"Substituted {orig_reg} -> {subst_reg} at 0x{addr:x}: '{disasm}' -> '{new_disasm}'"
                                )
                                mutated_bytes = binary.read_bytes(addr, orig_size)
                                record = self._record_mutation(
                                    function_address=func["addr"],
                                    start_address=addr,
                                    end_address=addr + orig_size - 1,
                                    original_bytes=original_bytes,
                                    mutated_bytes=mutated_bytes,
                                    original_disasm=insn.get("disasm", ""),
                                    mutated_disasm=new_disasm,
                                    mutation_kind="register_substitution",
                                    metadata={
                                        "original_register": orig_reg,
                                        "substitute_register": subst_reg,
                                        "structural_baseline": baseline,
                                    },
                                )
                                if self._validate_mutation_or_rollback(binary, record, mutation_checkpoint):
                                    continue
                                substituted_count += 1
                                func_mutations += 1
                            else:
                                logger.debug(f"Skipping substitution at 0x{addr:x}: new instruction too large")
                    except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                        logger.debug(f"Failed to substitute at 0x{addr:x}: {e}")

                if substituted_count > 0:
                    logger.info(
                        f"Substituted {orig_reg} -> {subst_reg} in {func.get('name')}: {substituted_count} instructions"
                    )
                    total_registers_substituted += 1

            if func_mutations > 0:
                mutations_applied += func_mutations
                functions_mutated += 1

        logger.info(
            f"Register substitution complete: {total_registers_substituted} registers "
            f"substituted in {functions_mutated} functions "
            f"({mutations_applied} total instruction changes)"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "registers_substituted": total_registers_substituted,
            "total_functions": len(functions),
        }
