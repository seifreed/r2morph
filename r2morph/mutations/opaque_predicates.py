"""
Opaque predicate injection mutation pass.

Injects conditionals that are always true or always false,
but appear complex to analysis tools.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
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

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply opaque predicate mutations.

        Args:
            binary: Binary to mutate

        Returns:
            Statistics dict
        """
        logger.info("Applying opaque predicate mutations")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0

        for func in functions:
            func_addr = func.get("offset", 0)
            func.get("name", f"0x{func_addr:x}")

            if func.get("size", 0) < 20:
                continue

            mutations = self._insert_opaque_predicates(binary, func)

            if mutations > 0:
                funcs_mutated += 1
                total_mutations += mutations

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
        }

    def _insert_opaque_predicates(self, binary: Binary, func: dict) -> int:
        """
        Insert opaque predicates in a function.

        Args:
            binary: Binary instance
            func: Function dict

        Returns:
            Number of mutations applied
        """
        func_addr = func.get("offset", 0)
        mutations = 0

        try:
            bb_json = binary.r2.cmd(f"afbj @ 0x{func_addr:x}")
            import json

            basic_blocks = json.loads(bb_json) if bb_json else []
        except Exception as e:
            logger.debug(f"Failed to get basic blocks: {e}")
            return 0

        num_predicates = min(self.max_predicates, len(basic_blocks) // 2)

        for _ in range(num_predicates):
            if random.random() > self.probability:
                continue

            if not basic_blocks:
                break

            bb = random.choice(basic_blocks)
            bb_addr = bb.get("addr", 0)

            predicate_type = random.choice(
                [
                    "always_true",
                    "always_false",
                ]
            )

            predicate_code = self._generate_predicate(binary, predicate_type, bb_addr)

            if predicate_code:
                logger.debug(f"Would insert {predicate_type} predicate at 0x{bb_addr:x}")
                mutations += 1

        return mutations

    def _generate_predicate(
        self, binary: Binary, predicate_type: str, insert_addr: int
    ) -> list[str]:
        """
        Generate opaque predicate assembly code.

        Args:
            binary: Binary instance
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
                    f"push {reg}",
                    f"imul {reg}, {reg}",
                    "test {reg}, {reg}",
                    "jns .real_code",
                    "jmp .fake_code",
                    ".real_code:",
                    f"pop {reg}",
                ],
                [
                    f"push {reg}",
                    f"and {reg}, 1",
                    "jz .real_code",
                    "jmp .real_code",
                    ".real_code:",
                    f"pop {reg}",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "je .real_code",
                    ".real_code:",
                ],
            ]

        else:
            predicates = [
                [
                    f"push {reg}",
                    f"imul {reg}, {reg}",
                    "test {reg}, {reg}",
                    "js .fake_code",
                    "jmp .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                    f"pop {reg}",
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
