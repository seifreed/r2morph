"""
Instruction expansion mutation pass.

Expands single instructions into multiple equivalent instructions.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from r2morph.mutations.base import MutationPass

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol

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

    # Only single-instruction expansions are supported. Multi-instruction
    # expansions (e.g., imul reg,3 -> mov tmp,reg; shl reg,1; add reg,tmp)
    # require temporary register allocation and are not yet implemented.
    #
    # FLAG SAFETY NOTE:
    # - inc/dec → add/sub: UNSAFE if CF is live (inc/dec preserve CF, add/sub modify it)
    # - mov reg, 0 → xor/sub: UNSAFE if ANY flags are live (mov doesn't touch flags)
    # These rules are EXCLUDED to avoid semantic corruption. Only flag-safe
    # expansions are included.
    EXPANSION_RULES = {
        "x86": {
            # imul → shl/add: both set CF/OF, safe equivalence
            ("imul", "reg", "2"): [
                [("shl", "reg", "1")],
                [("add", "reg", "reg")],
            ],
            ("imul", "reg", "4"): [
                [("shl", "reg", "2")],
            ],
            # shl 1 → add: both set same flags, safe equivalence
            ("shl", "reg", "1"): [
                [("add", "reg", "reg")],
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

    def configure_for_memory_constraints(self, factor: float) -> None:
        """Reduce expansion count for memory-efficient mode."""
        original = self.max_expansions
        self.max_expansions = max(1, int(self.max_expansions * factor))
        self.config["max_expansions_per_function"] = self.max_expansions
        if self.max_expansions != original:
            import logging
            logging.getLogger(__name__).debug(
                f"Memory-efficient: reduced max_expansions from {original} to {self.max_expansions}"
            )

    def _match_expansion_pattern(self, instruction: dict[str, Any], arch: str) -> list[list[tuple[str, ...]]]:
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
        operands = [p.strip(",") for p in parts[1:]] if len(parts) > 1 else []

        expansions: list[list[tuple[str, ...]]] = []

        size_specifiers = {"dword", "qword", "byte", "word", "ptr"}

        import re

        def is_register_operand(op: str) -> bool:
            if not op:
                return False
            if op in size_specifiers:
                return False
            if op.startswith("[") or op.startswith("-["):
                return False
            if op.startswith("0x") or op.startswith("-0x"):
                return False
            if op.isdigit() or (op.startswith("-") and op[1:].isdigit()):
                return False
            if op.endswith("h") or op.endswith("H"):
                hex_part = op[:-1]
                if all(c in "0123456789abcdefABCDEF" for c in hex_part):
                    return False
            if re.match(r"^\[.+\]$", op):
                return False
            if "," in op:
                return False
            return True

        def is_immediate_operand(op: str) -> bool:
            if not op:
                return False
            if op.isdigit():
                return True
            if op.startswith("-") and len(op) > 1:
                rest = op[1:]
                if rest.isdigit():
                    return True
                if rest.startswith("0x") and len(rest) > 2:
                    return all(c in "0123456789abcdefABCDEF" for c in rest[2:])
            if op.startswith("0x") and len(op) > 2:
                return all(c in "0123456789abcdefABCDEF" for c in op[2:])
            if op.endswith("h") or op.endswith("H"):
                hex_part = op[:-1]
                return all(c in "0123456789abcdefABCDEF" for c in hex_part)
            return False

        for pattern, expansion_list in self.EXPANSION_RULES[arch_family].items():
            pattern_mnemonic = pattern[0]
            pattern_ops = list(pattern[1:]) if len(pattern) > 1 else []

            if mnemonic != pattern_mnemonic:
                continue

            if not pattern_ops:
                expansions.extend(expansion_list)
                continue

            if len(pattern_ops) == 1 and pattern_ops[0] == "reg":
                if operands and is_register_operand(operands[0]):
                    expansions.extend(expansion_list)
                continue

            if len(pattern_ops) >= 1 and pattern_ops[0] == "reg":
                if not operands or not is_register_operand(operands[0]):
                    continue

                if len(pattern_ops) == 2:
                    second_pattern = pattern_ops[1]
                    if len(operands) >= 2:
                        second_op = operands[1]
                        if second_pattern == "reg":
                            if is_register_operand(second_op):
                                expansions.extend(expansion_list)
                        elif second_pattern == "0":
                            if second_op == "0" or second_op == "0x0":
                                expansions.extend(expansion_list)
                        elif second_pattern == "small_imm":
                            if is_immediate_operand(second_op):
                                try:
                                    val = int(second_op, 16) if second_op.startswith("0x") else int(second_op)
                                    if 0 <= val <= 255:
                                        expansions.extend(expansion_list)
                                except ValueError:
                                    pass
                        elif second_pattern.isdigit() or second_pattern.startswith("-"):
                            if is_immediate_operand(second_op):
                                try:
                                    expected = int(second_pattern)
                                    actual = int(second_op, 16) if second_op.startswith("0x") else int(second_op)
                                    if expected == actual:
                                        expansions.extend(expansion_list)
                                except ValueError:
                                    pass
                        else:
                            expansions.extend(expansion_list)
                else:
                    expansions.extend(expansion_list)

        return expansions

    def _build_instruction_from_pattern(self, pattern: tuple[str, ...], orig_parts: list[str]) -> str | None:
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

            target_register = None
            if len(orig_parts) > 1:
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

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply instruction expansion mutations to the binary.

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
                                    mutation_checkpoint = self._create_mutation_checkpoint("insn_expand")
                                    baseline = {}
                                    if self._validation_manager is not None:
                                        baseline = self._validation_manager.capture_structural_baseline(
                                            binary, func["addr"]
                                        )

                                    original_bytes = binary.read_bytes(addr, orig_size)

                                    if binary.write_bytes(addr, new_bytes):
                                        if new_size < orig_size:
                                            binary.nop_fill(addr + new_size, orig_size - new_size)

                                        mutated_bytes = binary.read_bytes(addr, orig_size)
                                        record = self._record_mutation(
                                            function_address=func["addr"],
                                            start_address=addr,
                                            end_address=addr + orig_size - 1,
                                            original_bytes=original_bytes if original_bytes else b"",
                                            mutated_bytes=mutated_bytes if mutated_bytes else new_bytes,
                                            original_disasm=orig_disasm,
                                            mutated_disasm=new_disasm,
                                            mutation_kind="instruction_expansion",
                                            metadata={
                                                "expansion_type": "single",
                                                "structural_baseline": baseline,
                                            },
                                        )

                                        if self._validation_manager is not None:
                                            outcome = self._validation_manager.validate_mutation(
                                                binary, record.to_dict()
                                            )
                                            if not outcome.passed and mutation_checkpoint is not None:
                                                if self._session is not None:
                                                    self._session.rollback_to(mutation_checkpoint)
                                                binary.reload()
                                                if self._records:
                                                    self._records.pop()
                                                if self._rollback_policy == "fail-fast":
                                                    raise RuntimeError("Mutation-level validation failed")
                                                continue

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
                    # Multi-instruction expansions are not yet implemented:
                    # they require temporary register allocation and space
                    # management that is beyond the current single-instruction
                    # in-place replacement strategy.
                    logger.debug(
                        f"Skipping multi-instruction expansion at 0x{addr:x} "
                        f"(not implemented: would require {len(chosen_expansion)} instructions)"
                    )

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
