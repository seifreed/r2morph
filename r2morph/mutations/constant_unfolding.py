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
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol
from r2morph.mutations.base import MutationPass

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
        """Get register mapping for architecture."""
        if bits == 64:
            return {
                "rax": ["rax", "eax", "r0"],
                "rbx": ["rbx", "ebx", "r3"],
                "rcx": ["rcx", "ecx", "r1"],
                "rdx": ["rdx", "edx", "r2"],
                "rsi": ["rsi", "esi"],
                "rdi": ["rdi", "edi"],
                "r8": ["r8", "r8d"],
                "r9": ["r9", "r9d"],
                "r10": ["r10", "r10d"],
                "r11": ["r11", "r11d"],
            }
        else:
            return {
                "eax": ["eax"],
                "ebx": ["ebx"],
                "ecx": ["ecx"],
                "edx": ["edx"],
                "esi": ["esi"],
                "edi": ["edi"],
            }

    def _unfold_zero(self, reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
        """
        Unfold setting register to zero.

        Args:
            reg: Register name
            bits: Architecture bits
            binary: Any instance for size calculation
            base_addr: Base address for assembly

        Returns:
            List of instruction strings or None
        """
        patterns = [
            f"xor {reg}, {reg}",
            f"sub {reg}, {reg}",
            f"and {reg}, 0",
        ]
        return [random.choice(patterns)]

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
        patterns = [
            f"xor {reg}, {reg}; inc {reg}",
            f"mov {reg}, 1",
        ]

        if random.random() < 0.5:
            return [f"xor {reg}, {reg}", f"inc {reg}"]
        return [f"mov {reg}, 1"]

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
        if value <= 0 or value > self.max_sequence:
            return None

        if value == 1:
            return [f"inc {reg}"]

        if value <= 3:
            return [f"inc {reg}"] * value

        half = value // 2
        remainder = value % 2

        result = [f"add {reg}, {half}"]
        if remainder:
            result.append(f"inc {reg}")
        return result

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
        if value <= 0 or value > self.max_sequence:
            return None

        if value == 1:
            return [f"dec {reg}"]

        if value <= 3:
            return [f"dec {reg}"] * value

        half = value // 2
        remainder = value % 2

        result = [f"sub {reg}, {half}"]
        if remainder:
            result.append(f"dec {reg}")
        return result

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
        total_size = 0
        for inst in instructions:
            if ";" in inst:
                parts = [p.strip() for p in inst.split(";")]
                for part in parts:
                    bytes_result = binary.assemble(part, base_addr)
                    total_size += len(bytes_result) if bytes_result else 0
            else:
                bytes_result = binary.assemble(inst, base_addr)
                total_size += len(bytes_result) if bytes_result else 0
        return total_size

    def _select_candidates(self, binary: Any, functions: list[dict[str, Any]]) -> list[tuple[dict, list]]:
        """
        Iterate functions, get disasm, and filter candidate instructions.

        Args:
            binary: Any instance
            functions: List of function dicts

        Returns:
            List of (func, selected_candidates) tuples
        """
        result = []
        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            candidates = []
            for insn in instructions:
                disasm = insn.get("disasm", "").lower()
                mnemonic = disasm.split()[0] if disasm else ""

                if mnemonic not in ["mov", "add", "sub", "push", "xor"]:
                    continue

                candidates.append(insn)

            selected = random.sample(candidates, min(self.max_unfolds, len(candidates)))
            if selected:
                result.append((func, selected))
        return result

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
                    parts = disasm.replace(",", " ").split()
                    if len(parts) < 2:
                        continue

                    mnemonic = parts[0]

                    unfolded = None

                    if mnemonic == "mov":
                        reg = parts[1]
                        value_str = parts[2] if len(parts) > 2 else ""

                        if value_str.isdigit() or (
                            value_str.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value_str[2:])
                        ):
                            value = int(value_str, 0)

                            if value == 0:
                                unfolded = self._unfold_zero(reg, bits, binary, func["addr"])
                                constants_unfolded += 1
                            elif value == 1:
                                unfolded = self._unfold_one(reg, bits, binary, func["addr"])
                                constants_unfolded += 1

                    elif mnemonic == "add":
                        reg = parts[1]
                        value_str = parts[2] if len(parts) > 2 else ""

                        if value_str.isdigit() or (
                            value_str.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value_str[2:])
                        ):
                            value = int(value_str, 0)

                            if 1 < value <= self.max_sequence:
                                unfolded = self._unfold_constant_add(reg, value, bits)
                                constants_unfolded += 1

                    elif mnemonic == "sub":
                        reg = parts[1]
                        value_str = parts[2] if len(parts) > 2 else ""

                        if value_str.isdigit() or (
                            value_str.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value_str[2:])
                        ):
                            value = int(value_str, 0)

                            if 1 < value <= self.max_sequence:
                                unfolded = self._unfold_constant_sub(reg, value, bits)
                                constants_unfolded += 1

                    if not unfolded:
                        continue

                    new_size = self._calculate_sequence_size(unfolded, binary, func["addr"])

                    if new_size == 0:
                        continue

                    if new_size > orig_size:
                        if self.size_limit > 1 and new_size > orig_size * self.size_limit:
                            continue
                        if new_size > orig_size + 16:
                            logger.debug(
                                f"Skipping unfold at 0x{addr:x}: size increase too large ({new_size} vs {orig_size})"
                            )
                            continue

                    mutation_checkpoint = self._create_mutation_checkpoint("unfold")
                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])
                    original_bytes = binary.read_bytes(addr, orig_size)

                    all_bytes = b""
                    for inst in unfolded:
                        inst_bytes = binary.assemble(inst, func["addr"])
                        if inst_bytes:
                            all_bytes += inst_bytes

                    if not all_bytes:
                        continue

                    if len(all_bytes) > orig_size:
                        logger.debug(f"Skipping unfold at 0x{addr:x}: size too large ({len(all_bytes)} > {orig_size})")
                        continue

                    if not binary.write_bytes(addr, all_bytes):
                        continue

                    if len(all_bytes) < orig_size:
                        binary.nop_fill(addr + len(all_bytes), orig_size - len(all_bytes))

                    mutated_bytes = binary.read_bytes(addr, orig_size)
                    record = self._record_mutation(
                        function_address=func["addr"],
                        start_address=addr,
                        end_address=addr + orig_size - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=mutated_bytes,
                        original_disasm=disasm,
                        mutated_disasm="; ".join(unfolded),
                        mutation_kind="constant_unfolding",
                        metadata={
                            "unfolded_instructions": len(unfolded),
                            "original_size": orig_size,
                            "new_size": len(all_bytes),
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

                    logger.info(f"Unfolded constant: '{disasm}' -> '{'; '.join(unfolded)}' at 0x{addr:x}")
                    func_mutations += 1
                    mutations_applied += 1
                    size_increase += len(all_bytes) - orig_size

                except Exception as e:
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
