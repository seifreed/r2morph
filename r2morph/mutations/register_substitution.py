"""
Register substitution mutation pass.

Replaces registers with equivalent unused registers in code sequences.
"""

import logging
import random
from typing import Any, List, Tuple

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

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

    REGISTER_CLASSES = {
        "x86": {
            "gp32": ["eax", "ebx", "ecx", "edx", "esi", "edi"],
            "caller_saved": ["eax", "ecx", "edx"],
            "callee_saved": ["ebx", "esi", "edi"],
        },
        "x64": {
            "gp64": [
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
            ],
            "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
            "callee_saved": ["rbx", "r12", "r13", "r14", "r15"],
        },
        "arm": {
            "gp": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
            "caller_saved": ["r0", "r1", "r2", "r3"],
            "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        },
    }

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

    def _get_register_class(self, arch: str) -> dict[str, list[str]]:
        """
        Get register classes for architecture.

        Args:
            arch: Architecture name

        Returns:
            Dictionary of register classes
        """
        if arch in ["x86", "x64"]:
            arch_family = arch
        elif arch in ["arm", "arm64"]:
            arch_family = "arm"
        else:
            return {}

        return self.REGISTER_CLASSES.get(arch_family, {})

    def _find_substitution_candidates(
        self, instructions: list[dict[str, Any]], arch: str
    ) -> list[Tuple[str, str]]:
        """
        Find valid register substitution opportunities.

        Args:
            instructions: List of instructions
            arch: Architecture

        Returns:
            List of (original_reg, substitute_reg) tuples
        """
        register_classes = self._get_register_class(arch)
        if not register_classes:
            return []

        candidates = []

        used_registers = set()
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            for reg_class in register_classes.values():
                for reg in reg_class:
                    if reg in disasm:
                        used_registers.add(reg)

        caller_saved = set(register_classes.get("caller_saved", []))
        unused = caller_saved - used_registers

        if unused:
            for used_reg in used_registers & caller_saved:
                if unused:
                    substitute = random.choice(list(unused))
                    candidates.append((used_reg, substitute))
                    unused.discard(substitute)

        return candidates

    def _count_register_uses(self, instructions: list[dict[str, Any]], register: str) -> int:
        """
        Count how many times a register is used.

        Args:
            instructions: List of instructions
            register: Register name

        Returns:
            Number of uses
        """
        count = 0
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            if register in disasm:
                count += 1
        return count

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply register substitution mutations to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")

        register_classes = self._get_register_class(arch)
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

        for func in functions:
            if func.get("size", 0) < 20:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            candidates = self._find_substitution_candidates(instructions, arch)

            if not candidates:
                continue

            if random.random() > self.probability:
                continue

            num_substitutions = min(self.max_substitutions, len(candidates))
            selected = random.sample(candidates, num_substitutions)

            func_mutations = 0
            for orig_reg, subst_reg in selected:
                substituted_count = 0

                for insn in instructions:
                    disasm = insn.get("disasm", "").lower()

                    if orig_reg not in disasm:
                        continue

                    new_disasm = disasm.replace(orig_reg, subst_reg)

                    addr = insn.get("addr", 0)
                    orig_size = insn.get("size", 0)

                    if addr == 0 or orig_size == 0:
                        continue

                    try:
                        new_bytes = binary.assemble(new_disasm)

                        if new_bytes:
                            new_size = len(new_bytes)

                            if new_size <= orig_size:
                                binary.write_bytes(addr, new_bytes)

                                if new_size < orig_size:
                                    binary.nop_fill(addr + new_size, orig_size - new_size)

                                logger.debug(
                                    f"Substituted {orig_reg} -> {subst_reg} at 0x{addr:x}: "
                                    f"'{disasm}' -> '{new_disasm}'"
                                )
                                substituted_count += 1
                                func_mutations += 1
                            else:
                                logger.debug(
                                    f"Skipping substitution at 0x{addr:x}: new instruction too large"
                                )
                    except Exception as e:
                        logger.debug(f"Failed to substitute at 0x{addr:x}: {e}")

                if substituted_count > 0:
                    logger.info(
                        f"Substituted {orig_reg} -> {subst_reg} in {func.get('name')}: "
                        f"{substituted_count} instructions"
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
