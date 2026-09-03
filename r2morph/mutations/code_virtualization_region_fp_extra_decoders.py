"""Additional register-only SIMD decoders kept outside the main FP decoder."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region_decoders import _register_operand
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _parse_xmm_operand,
    _parse_ymm_operand,
)

_PART_COUNT = 2
_OPERAND_COUNT = 3
_EXTRA_VEX_OPERATIONS = {"vpackusdw": "packusdw", "vpshufb": "pshufb", "vpmaxub": "pmaxub"}
_VEX_LANE_EXTRACT = frozenset({"vextractf128", "vextracti128"})
_VEX_FP_TO_INT = {"vcvttsd2si": 64, "vcvttss2si": 32}


def _decode_fp_vex_convert(text: str) -> tuple[Any, ...] | None:
    """Decode two-operand VEX floating-point to integer conversions."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT or "," not in parts[1]:
        return None
    fp_width = _VEX_FP_TO_INT.get(parts[0].lower())
    if fp_width is None:
        return None
    destination_text, source_text = (token.strip() for token in parts[1].split(",", 1))
    destination = _register_operand(destination_text.lower())
    source = _parse_xmm_operand(source_text)
    if destination is None or source is None:
        return None
    return ("cvtf2i", fp_width, destination[1], destination[0], source)


def _decode_fp_vex_lane_extract(text: str) -> tuple[Any, ...] | None:
    """Decode a VEX.128 lane extraction into the common move item shape."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT or parts[0].lower() not in _VEX_LANE_EXTRACT:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _OPERAND_COUNT:
        return None
    destination = _parse_xmm_operand(operands[0])
    source = _parse_ymm_operand(operands[1])
    if destination is None or source is None:
        return None
    try:
        lane = int(operands[2], 0)
    except ValueError:
        return None
    if lane not in (0, 1):
        return None
    return ("fpmovvex", f"extract{lane}", destination, source)


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
