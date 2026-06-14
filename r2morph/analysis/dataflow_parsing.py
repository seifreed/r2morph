"""Pure parsing helpers for dataflow analysis."""

from __future__ import annotations

from r2morph.analysis._register_names import X86_REGISTER_NAMES


def extract_registers_from_operand(operand: str) -> set[tuple[str, int]]:
    """Extract register names and sizes from an operand string."""
    registers: set[tuple[str, int]] = set()
    operand = operand.lower()

    for reg in X86_REGISTER_NAMES:
        if reg in operand:
            size = 64 if reg.startswith("r") and "d" not in reg and "w" not in reg and "b" not in reg else 32
            if reg.endswith("d"):
                size = 32
            elif reg.endswith("w"):
                size = 16
            elif reg.endswith("b"):
                size = 8
            registers.add((reg, size))

    return registers
