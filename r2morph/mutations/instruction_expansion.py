"""
Instruction expansion mutation pass.

Expands single instructions into multiple equivalent instructions.
"""

import logging
import random
from typing import Any, List, Optional, Tuple

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


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

    EXPANSION_RULES = {
        "x86": {
            ("inc", "reg"): [
                [("add", "reg", "1")],
                [("sub", "reg", "-1")],
            ],
            ("dec", "reg"): [
                [("sub", "reg", "1")],
                [("add", "reg", "-1")],
            ],
            ("imul", "reg", "2"): [
                [("shl", "reg", "1")],
                [("add", "reg", "reg")],
            ],
            ("imul", "reg", "3"): [
                [("mov", "temp", "reg"), ("shl", "reg", "1"), ("add", "reg", "temp")],
            ],
            ("imul", "reg", "4"): [
                [("shl", "reg", "2")],
            ],
            ("imul", "reg", "5"): [
                [("mov", "temp", "reg"), ("shl", "reg", "2"), ("add", "reg", "temp")],
            ],
            ("shl", "reg", "1"): [
                [("add", "reg", "reg")],
            ],
            ("neg", "reg"): [
                [("not", "reg"), ("inc", "reg")],
            ],
            ("mov", "reg", "0"): [
                [("xor", "reg", "reg")],
                [("sub", "reg", "reg")],
                [("and", "reg", "0")],
            ],
            ("mov", "reg", "small_imm"): [
                [("xor", "reg", "reg"), ("add", "reg", "imm")],
            ],
        }
    }

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

    def _match_expansion_pattern(
        self, instruction: dict[str, Any], arch: str
    ) -> list[list[Tuple[str, ...]]]:
        """
        Check if instruction matches any expansion pattern.

        Args:
            instruction: Instruction dictionary from r2
            arch: Architecture (x86, x64, arm, etc.)

        Returns:
            List of possible expansion sequences
        """
        arch_family = "x86" if arch in ["x86", "x64"] else arch

        if arch_family not in self.EXPANSION_RULES:
            return []

        disasm = instruction.get("disasm", "").lower()
        parts = disasm.split()

        if not parts:
            return []

        mnemonic = parts[0]
        expansions = []

        for pattern, expansion_list in self.EXPANSION_RULES[arch_family].items():
            pattern_mnemonic = pattern[0]

            if mnemonic == pattern_mnemonic:
                expansions.extend(expansion_list)

        return expansions

    def _build_instruction_from_pattern(
        self, pattern: tuple[str, ...], orig_parts: list[str]
    ) -> str | None:
        """
        Build a concrete instruction from a pattern and original instruction parts.

        Args:
            pattern: Expansion pattern tuple (mnemonic, arg1, arg2, ...)
            orig_parts: Parts of original instruction [mnemonic, operands...]

        Returns:
            Assembly string or None if cannot build
        """
        try:
            new_mnemonic = pattern[0]
            new_operands = []

            # Extract the target register from original instruction
            target_register = None
            if len(orig_parts) > 1:
                # Get first operand (destination register)
                candidate = orig_parts[1].strip(",").strip()

                # Validation: reject size specifiers and memory operands
                # Size specifiers like "dword", "qword" appear in instructions like:
                #   "mov dword [rsp], eax" → parts[1] = "dword"
                size_specifiers = {"dword", "qword", "byte", "word", "ptr"}

                if candidate and candidate not in size_specifiers and not candidate.startswith("["):
                    target_register = candidate
                else:
                    # Not a valid register operand, skip this expansion
                    return None

            for _i, param in enumerate(pattern[1:], start=1):
                if param == "reg":
                    if target_register:
                        new_operands.append(target_register)
                    else:
                        return None
                elif param in ["1", "2", "3", "4", "5", "-1"]:
                    new_operands.append(param)
                elif param == "0":
                    new_operands.append("0")
                else:
                    new_operands.append(param)

            if new_operands:
                return f"{new_mnemonic} {', '.join(new_operands)}"
            else:
                return new_mnemonic

        except Exception as e:
            logger.debug(f"Failed to build instruction from pattern {pattern}: {e}")
            return None

    def _get_expansion_size_increase(self, expansion: list[tuple[str, ...]]) -> int:
        """
        Calculate how many bytes the expansion adds.

        Args:
            expansion: Expansion sequence

        Returns:
            Estimated size increase in bytes
        """
        original_size = 3
        expanded_size = len(expansion) * 3
        return expanded_size - original_size

    def _is_safe_to_expand(self, instruction: dict[str, Any], function_size: int) -> bool:
        """
        Check if it's safe to expand this instruction.

        Args:
            instruction: Instruction to potentially expand
            function_size: Current function size

        Returns:
            True if safe to expand
        """
        insn_type = instruction.get("type", "")
        if insn_type in ["jmp", "cjmp", "call", "ret", "ujmp"]:
            return False

        if function_size > 1000:
            return False

        return True

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply instruction expansion mutations to the binary.

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
            if func.get("size", 0) < 20:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            func_expansions = 0
            func_size_increase = 0

            for insn in instructions:
                if func_expansions >= self.max_expansions:
                    break

                if not self._is_safe_to_expand(insn, func.get("size", 0)):
                    continue

                expansions = self._match_expansion_pattern(insn, arch_family)

                if not expansions:
                    continue

                if random.random() > self.probability:
                    continue

                chosen_expansion = random.choice(expansions)

                if len(chosen_expansion) > self.max_expansion_size:
                    continue

                addr = insn.get("addr", 0)
                orig_size = insn.get("size", 0)
                orig_disasm = insn.get("disasm", "")

                if addr == 0 or orig_size == 0:
                    continue

                if len(chosen_expansion) == 1:
                    try:
                        parts = orig_disasm.lower().split()

                        pattern = chosen_expansion[0]
                        new_disasm = self._build_instruction_from_pattern(pattern, parts)

                        if new_disasm:
                            new_bytes = binary.assemble(new_disasm, func["addr"])

                            if new_bytes:
                                new_size = len(new_bytes)

                                if new_size <= orig_size:
                                    binary.write_bytes(addr, new_bytes)

                                    if new_size < orig_size:
                                        binary.nop_fill(addr + new_size, orig_size - new_size)

                                    size_inc = new_size - orig_size
                                    logger.info(
                                        f"Expanded '{orig_disasm}' -> '{new_disasm}' at 0x{addr:x} "
                                        f"({orig_size} -> {new_size} bytes)"
                                    )
                                    func_expansions += 1
                                    func_size_increase += size_inc
                                else:
                                    logger.debug(
                                        f"Skipping expansion at 0x{addr:x}: new instruction too large "
                                        f"({new_size} > {orig_size})"
                                    )
                    except Exception as e:
                        logger.debug(f"Failed to expand at 0x{addr:x}: {e}")
                else:
                    logger.debug(
                        f"Skipping multi-instruction expansion at 0x{addr:x} "
                        f"(would require {len(chosen_expansion)} instructions)"
                    )

            if func_expansions > 0:
                mutations_applied += func_expansions
                total_expansions += func_expansions
                size_increase += func_size_increase
                functions_mutated += 1

                logger.info(
                    f"Expanded {func_expansions} instructions in {func.get('name')} "
                    f"(+{func_size_increase} bytes)"
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
