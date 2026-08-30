"""Additional register-only SIMD decoders kept outside the main FP decoder."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _parse_xmm_operand,
    _parse_ymm_operand,
)

_PART_COUNT = 2
_OPERAND_COUNT = 3
_EXTRA_VEX_OPERATIONS = {"vpshufb": "pshufb"}


def _decode_fp_vex_extra(text: str) -> tuple[Any, ...] | None:
    """Decode register-only VEX SIMD operations not in the core FP decoder."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT:
        return None
    operation = _EXTRA_VEX_OPERATIONS.get(parts[0].lower())
    operands = [token.strip() for token in parts[1].split(",")]
    if operation is None or len(operands) != _OPERAND_COUNT:
        return None
    if operands[0].lower().startswith("ymm"):
        registers = tuple(_parse_ymm_operand(operand) for operand in operands)
        if any(register is None for register in registers):
            return None
        return ("fppackedvex256", operation, *registers)
    registers = tuple(_parse_xmm_operand(operand) for operand in operands)
    if any(register is None for register in registers):
        return None
    return ("fppackedvex", operation, *registers)
