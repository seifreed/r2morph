"""Pure parsing helpers for dataflow analysis."""

from __future__ import annotations

import re

from r2morph.analysis._register_names import X86_REGISTER_NAMES


def extract_registers_from_operand(operand: str) -> set[tuple[str, int]]:
    """Extract register names and sizes from an operand string."""
    registers: set[tuple[str, int]] = set()
    operand = operand.lower()

    for reg in X86_REGISTER_NAMES:
        if re.search(rf"(?<![a-z0-9_]){re.escape(reg)}(?![a-z0-9_])", operand):
            if reg.startswith("ymm"):
                size = 256
            elif reg.startswith("xmm"):
                size = 128
            elif reg.endswith("d"):
                size = 32
            elif reg.endswith("w"):
                size = 16
            elif reg.endswith("b"):
                size = 8
            else:
                size = 64 if reg.startswith("r") else 32
            registers.add((reg, size))

    return registers
