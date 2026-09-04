"""
Register substitution mutation pass.

Replaces registers with equivalent unused registers in code sequences.
"""

from __future__ import annotations

import logging
from typing import Any

from r2morph.core.constants import ARCH_BITS_64
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

_PreparedSubstitution = tuple[dict[str, Any], str, bytes, str, str]

_UNSAFE_MNEMONICS = {
    "xlat",
    "movabs",
    "cmovz",
    "cmovnz",
    "cmove",
    "cmovne",
    "setne",
    "sete",
    "setz",
    "setnz",
    "lock",
    "xadd",
    "cmpxchg",
}


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
    ) -> list[tuple[dict[str, Any], list[dict[str, Any]], list[tuple[str, str]]]]:
        return select_candidates(binary, functions, arch, self.probability, self.max_substitutions)

    @staticmethod
    def _register_only_in_memory(disasm: str, register: str) -> bool:
        if "[" not in disasm or "]" not in disasm:
            return False
        before_memory, remainder = disasm.split("[", maxsplit=1)
        memory, after_memory = remainder.split("]", maxsplit=1)
        return register in memory and register not in before_memory + after_memory

    def _substituted_disasm(self, instruction: dict[str, Any], original: str, substitute: str) -> str | None:
        disasm = str(instruction.get("disasm", "")).lower()
        if original not in disasm:
            return None
        mnemonic = disasm.split()[0] if disasm else ""
        if mnemonic in _UNSAFE_MNEMONICS:
            return None
        if mnemonic in ("movzx", "movsx") and not self._is_safe_size_extension_substitution(
            disasm, original, substitute
        ):
            return None
        if mnemonic == "lea" and not self._is_safe_lea_substitution(disasm, original, substitute):
            return None
        if self._register_only_in_memory(disasm, original):
            return None
        return disasm.replace(original, substitute)

    def _apply_instruction_substitution(
        self,
        binary: Any,
        function: dict[str, Any],
        prepared: _PreparedSubstitution,
    ) -> bool:
        instruction, replacement, new_bytes, original_register, substitute_register = prepared
        address = instruction.get("addr", 0)
        original_size = instruction.get("size", 0)
        checkpoint = self._create_mutation_checkpoint("reg")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        original_bytes = binary.read_bytes(address, original_size)
        if not binary.write_bytes(address, new_bytes):
            return False
        if len(new_bytes) < original_size and not binary.nop_fill(
            address + len(new_bytes), original_size - len(new_bytes)
        ):
            self._rollback_uncommitted(
                binary,
                checkpoint,
                reason="Register-substitution NOP fill failed; aborting (fail-fast)",
            )
            return False
        logger.debug(
            f"Substituted {original_register} -> {substitute_register} at 0x{address:x}: "
            f"'{instruction.get('disasm', '').lower()}' -> '{replacement}'"
        )
        record = self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + original_size - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(address, original_size),
            original_disasm=instruction.get("disasm", ""),
            mutated_disasm=replacement,
            mutation_kind="register_substitution",
            metadata={
                "original_register": original_register,
                "substitute_register": substitute_register,
                "structural_baseline": baseline,
            },
        )
        return not self._validate_mutation_or_rollback(binary, record, checkpoint)

    def _prepare_substitution(
        self,
        binary: Any,
        function: dict[str, Any],
        instructions: list[dict[str, Any]],
        original_register: str,
        substitute_register: str,
    ) -> list[_PreparedSubstitution] | None:
        prepared: list[_PreparedSubstitution] = []
        for instruction in instructions:
            disasm = str(instruction.get("disasm", "")).lower()
            if original_register not in disasm:
                continue
            replacement = self._substituted_disasm(instruction, original_register, substitute_register)
            address = instruction.get("addr", 0)
            original_size = instruction.get("size", 0)
            if replacement is None or address == 0 or original_size == 0:
                return None
            new_bytes = binary.assemble(replacement, function["addr"])
            if not new_bytes or len(new_bytes) > original_size:
                return None
            prepared.append((instruction, replacement, new_bytes, original_register, substitute_register))
        return prepared or None

    def _restore_substitution(
        self,
        binary: Any,
        originals: list[tuple[int, bytes]],
        record_count: int,
    ) -> None:
        restored = True
        for address, original in originals:
            restored = binary.write_bytes(address, original) and restored
        if not restored:
            raise RuntimeError("Failed to restore partial register substitution")
        del self._records[record_count:]

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply register substitution mutations to the binary.

        Args:
            binary: Object satisfying BinaryAccessProtocol

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        self._ensure_analyzed(binary)

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 0)

        arch_key = arch
        if arch == "x86" and bits == ARCH_BITS_64:
            arch_key = "x64"
        elif arch == "arm" and bits == ARCH_BITS_64:
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

        for func, instructions, selected in self._select_candidates(binary, functions, arch_key):
            func_mutations = 0
            for orig_reg, subst_reg in selected:
                prepared = self._prepare_substitution(binary, func, instructions, orig_reg, subst_reg)
                if prepared is None:
                    continue
                originals = [
                    (insn["addr"], binary.read_bytes(insn["addr"], insn["size"])) for insn, _, _, _, _ in prepared
                ]
                record_count = len(self._records)
                for prepared_instruction in prepared:
                    insn = prepared_instruction[0]
                    address = insn.get("addr", 0)
                    try:
                        applied = self._apply_instruction_substitution(
                            binary,
                            func,
                            prepared_instruction,
                        )
                    except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
                        logger.debug(f"Failed to substitute at 0x{address:x}: {error}")
                        applied = False
                    if not applied:
                        self._restore_substitution(binary, originals, record_count)
                        break
                else:
                    substituted_count = len(prepared)
                    func_mutations += substituted_count

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
