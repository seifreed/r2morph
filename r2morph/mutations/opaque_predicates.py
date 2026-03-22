"""
Opaque predicate injection mutation pass.

Injects conditionals that are always true or always false,
but appear complex to analysis tools.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import OPAQUE_PREDICATE_MIN_FUNCTION_SIZE

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class OpaquePredicatePass(MutationPass):
    """
    Inserts opaque predicates (always-true or always-false conditions).

    Opaque predicates add complexity to control flow without changing semantics.
    Makes static analysis harder while preserving dynamic behavior.

    Examples:
        - if (x * x >= 0) { real_code; } // Always true
        - if ((x % 2 == 0) || (x % 2 == 1)) { real_code; } // Always true
        - if (x * x < 0) { fake_code; } // Always false
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize opaque predicate pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="OpaquePredicates", config=config)
        self.max_predicates = self.config.get("max_predicates_per_function", 3)
        self.probability = self.config.get("probability", 0.3)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply opaque predicate mutations.

        Args:
            binary: Any to mutate

        Returns:
            Statistics dict
        """
        self._reset_random()
        logger.info("Applying opaque predicate mutations")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0

        for func in functions:
            func_addr = func.get("addr", 0)

            if func.get("size", 0) < OPAQUE_PREDICATE_MIN_FUNCTION_SIZE:
                continue

            mutations = self._insert_opaque_predicates(binary, func)

            if mutations > 0:
                funcs_mutated += 1
                total_mutations += mutations

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
        }

    def _insert_opaque_predicates(self, binary: Any, func: dict) -> int:
        """
        Insert opaque predicates in a function.

        Args:
            binary: Any instance
            func: Function dict

        Returns:
            Number of mutations applied
        """
        func_addr = func.get("addr", 0)
        mutations = 0

        try:
            bb_json = binary.r2.cmd(f"afbj @ 0x{func_addr:x}")
            import json

            basic_blocks = json.loads(bb_json) if bb_json else []
        except (ValueError, OSError, BrokenPipeError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to get basic blocks: {e}")
            return 0

        num_predicates = min(self.max_predicates, len(basic_blocks) // 2)

        mutation_checkpoint = self._create_mutation_checkpoint("opaque_predicate")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)

        for _ in range(num_predicates):
            if random.random() > self.probability:
                continue

            if not basic_blocks:
                break

            bb = random.choice(basic_blocks)
            bb_addr = bb.get("addr", 0)
            bb_size = bb.get("size", 0)

            predicate_type = random.choice(
                [
                    "always_true",
                    "always_false",
                ]
            )

            predicate_code = self._generate_predicate(binary, predicate_type, bb_addr)

            if predicate_code:
                assembled = self._assemble_predicate(binary, predicate_code, bb_addr)
                if assembled and len(assembled) <= bb_size:
                    orig_bytes_hex = ""
                    if binary.r2:
                        orig_bytes_hex = binary.r2.cmd(f"p8 {len(assembled)} @ 0x{bb_addr:x}") or ""
                    orig_bytes = b""
                    if orig_bytes_hex.strip():
                        try:
                            orig_bytes = bytes.fromhex(orig_bytes_hex.strip())
                        except ValueError:
                            logger.debug(f"Invalid hex in original bytes: {orig_bytes_hex[:20]}...")
                            orig_bytes = b""

                    if binary.write_bytes(bb_addr, assembled):
                        self._record_mutation(
                            function_address=func_addr,
                            start_address=bb_addr,
                            end_address=bb_addr + len(assembled) - 1,
                            original_bytes=orig_bytes,
                            mutated_bytes=assembled,
                            original_disasm=f"block at 0x{bb_addr:x}",
                            mutated_disasm=f"opaque {predicate_type} predicate",
                            mutation_kind="opaque_predicate",
                            metadata={"predicate_type": predicate_type, "structural_baseline": baseline},
                        )
                        mutations += 1
                        logger.debug(f"Inserted {predicate_type} predicate at 0x{bb_addr:x}")

        if mutations > 0 and self._validation_manager is not None and mutation_checkpoint is not None:
            if self._records:
                outcome = self._validation_manager.validate_mutation(binary, self._records[-1].to_dict())
                if not outcome.passed:
                    if self._session is not None:
                        self._session.rollback_to(mutation_checkpoint)
                    binary.reload()
                    if self._records:
                        self._records.pop()
                    if self._rollback_policy == "fail-fast":
                        raise RuntimeError("Mutation-level validation failed")
                    return 0

        return mutations

    def _assemble_predicate(self, binary: Any, instructions: list[str], addr: int) -> bytes | None:
        """
        Assemble predicate instructions into bytes.

        Args:
            binary: Any instance
            instructions: List of assembly instructions
            addr: Address to assemble at

        Returns:
            Assembled bytes or None on failure
        """
        assembled = b""
        current_addr = addr

        for insn in instructions:
            if insn.startswith("."):
                continue

            insn_bytes = binary.assemble(insn, current_addr)
            if insn_bytes is None:
                return None

            assembled += insn_bytes
            current_addr += len(insn_bytes)

        return assembled if assembled else None

    def _generate_predicate(self, binary: Any, predicate_type: str, insert_addr: int) -> list[str]:
        """
        Generate opaque predicate assembly code.

        Args:
            binary: Any instance
            predicate_type: "always_true" or "always_false"
            insert_addr: Address to insert at

        Returns:
            List of assembly instructions
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86")
        bits = arch_info.get("bits", 64)

        if "x86" in arch.lower():
            return self._generate_x86_predicate(predicate_type, bits)
        elif "arm" in arch.lower():
            return self._generate_arm_predicate(predicate_type, bits)

        return []

    def _generate_x86_predicate(self, predicate_type: str, bits: int) -> list[str]:
        """
        Generate x86 opaque predicate.

        Args:
            predicate_type: Type of predicate
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "rax" if bits == 64 else "eax"

        if predicate_type == "always_true":
            predicates = [
                [
                    f"xor {reg}, {reg}",
                    f"test {reg}, {reg}",
                    "jz .real_code",
                    ".real_code:",
                ],
                [
                    f"mov {reg}, 0",
                    f"test {reg}, {reg}",
                    "jz .real_code",
                    ".real_code:",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "je .real_code",
                    ".real_code:",
                ],
                [
                    f"push {reg}",
                    f"xor {reg}, {reg}",
                    f"test {reg}, {reg}",
                    "jz .real_code",
                    "nop",
                    ".real_code:",
                    f"pop {reg}",
                ],
            ]

        else:
            predicates = [
                [
                    f"mov {reg}, 0",
                    f"test {reg}, {reg}",
                    "jnz .fake_code",
                    "jmp .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "jne .fake_code",
                    "jmp .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                ],
            ]

        return random.choice(predicates)

    def _generate_arm_predicate(self, predicate_type: str, bits: int) -> list[str]:
        """
        Generate ARM opaque predicate.

        Args:
            predicate_type: Type of predicate
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "x0" if bits == 64 else "r0"

        if predicate_type == "always_true":
            predicates = [
                [
                    f"mul {reg}, {reg}, {reg}",
                    f"cmp {reg}, #0",
                    "b.ge .real_code",
                    ".real_code:",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "b.eq .real_code",
                    ".real_code:",
                ],
            ]

        else:
            predicates = [
                [
                    f"mul {reg}, {reg}, {reg}",
                    f"cmp {reg}, #0",
                    "b.lt .fake_code",
                    "b .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                ],
            ]

        return random.choice(predicates)
