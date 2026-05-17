"""x86/ARM opaque-predicate instruction-sequence generator.

Extracted verbatim from ControlFlowFlatteningPass (clean-arch CFF slice
3): pure sequence builders with no pass state, consumed only by
ControlFlowFlatteningPass._add_opaque_predicate within the mutations/
layer. Plain collaborator (no protocol) per the ValidationManager
decomposition precedent — a protocol would be premature abstraction for
an internal-only seam.
"""

from __future__ import annotations

import random


class OpaquePredicateGenerator:
    """Builds register-preserving opaque-predicate instruction sequences."""

    @staticmethod
    def get_x86(bits: int) -> list[list[str]]:
        """
        Get x86 opaque predicate instruction sequences.

        Each sequence is designed to:
        1. Preserve all register values (push/pop)
        2. Set flags in a predictable way that's hard to analyze statically
        3. Be small enough to fit in slack space

        Args:
            bits: 32 or 64 bit mode

        Returns:
            List of instruction sequences
        """
        if bits == 64:
            regs = ["rax", "rbx", "rcx", "rdx"]
        else:
            regs = ["eax", "ebx", "ecx", "edx"]

        reg = random.choice(regs)

        predicates = [
            # x^2 | 1 is always non-zero → ZF=0 after test → opaque true.
            # push saves original reg; pop restores it. On x86 pop does NOT
            # modify flags, so ZF=0 from test persists through pop.
            [
                f"push {reg}",
                f"imul {reg}, {reg}",
                f"or {reg}, 1",
                f"test {reg}, {reg}",
                f"pop {reg}",
            ],
            # (x | 1) != 0 is always true: opaque true
            [
                f"push {reg}",
                f"or {reg}, 1",
                f"test {reg}, {reg}",
                f"pop {reg}",
            ],
            # x & (x-1) == x when x is 0 (ZF set): always-zero predicate
            [
                f"xor {reg}, {reg}",
                f"test {reg}, {reg}",
            ],
            # Save and restore flags for transparent predicate insertion
            [
                "pushf" if bits == 32 else "pushfq",
                "nop",
                "popf" if bits == 32 else "popfq",
            ],
            # 2*(x/2) always has bit 0 clear: opaque false on odd test
            [
                f"push {reg}",
                f"mov {reg}, 42",
                f"and {reg}, 0xFFFFFFFE" if bits == 32 else f"and {reg}, 0xFFFFFFFFFFFFFFFE",
                f"test {reg}, 1",
                f"pop {reg}",
            ],
        ]

        return predicates

    @staticmethod
    def get_arm(bits: int) -> list[list[str]]:
        """
        Get ARM opaque predicate instruction sequences.

        Args:
            bits: 32 or 64 bit mode

        Returns:
            List of instruction sequences
        """
        if bits == 64:
            regs = ["x9", "x10", "x11"]  # Temporary registers
        else:
            regs = ["r4", "r5", "r6"]

        reg = random.choice(regs)

        predicates = [
            # Simple flag manipulation
            [
                f"mov {reg}, #1",
                f"tst {reg}, #1",  # Sets flags
                f"mov {reg}, #0",
            ],
            # XOR-based predicate
            [
                f"eor {reg}, {reg}, {reg}",  # Always 0
                f"cmp {reg}, #0",  # Always equal
            ],
        ]

        return predicates
