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
_BROADCAST_OPERAND_COUNT = 2
_BYTE_WIDTH_BITS = 8
_DWORD_WIDTH_BITS = 32
_QWORD_WIDTH_BITS = 64
_EXTRA_VEX_OPERATIONS = {"vpackusdw": "packusdw", "vpshufb": "pshufb", "vpmaxub": "pmaxub"}
_VEX_LANE_EXTRACT = frozenset({"vextractf128", "vextracti128"})
_VEX_FP_TO_INT = {"vcvttsd2si": _QWORD_WIDTH_BITS, "vcvttss2si": _DWORD_WIDTH_BITS}
_VEX_GP_EXTRACT = {"vpextrb": 8, "vpextrd": _DWORD_WIDTH_BITS, "vpextrq": _QWORD_WIDTH_BITS}


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


def _decode_fp_vex_gp_extract(text: str) -> tuple[Any, ...] | None:
    """Decode a VEX packed-lane extraction into a GP register."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT or parts[0].lower() not in _VEX_GP_EXTRACT:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _OPERAND_COUNT:
        return None
    destination = _register_operand(operands[0].lower())
    source = _parse_xmm_operand(operands[1])
    if destination is None or source is None:
        return None
    width = _VEX_GP_EXTRACT[parts[0].lower()]
    expected_destination_width = _QWORD_WIDTH_BITS if width == _QWORD_WIDTH_BITS else _DWORD_WIDTH_BITS
    if destination[1] != expected_destination_width:
        return None
    try:
        immediate = int(operands[2], 0)
    except ValueError:
        return None
    limit = 2 if width == _QWORD_WIDTH_BITS else 16 if width == _BYTE_WIDTH_BITS else 4
    return ("fpmovvexextract", width, destination[0], source, immediate) if 0 <= immediate < limit else None


def _decode_fp_vex_extra(text: str) -> tuple[Any, ...] | None:
    """Decode register-only VEX SIMD operations not in the core FP decoder."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT:
        return None
    broadcast = _decode_fp_vex_broadcast(text)
    if broadcast is not None:
        return broadcast
    operation = _EXTRA_VEX_OPERATIONS.get(parts[0].lower())
    operands = [token.strip() for token in parts[1].split(",")]
    if operation is None or len(operands) != _OPERAND_COUNT:
        return None
    is_ymm = operands[0].lower().startswith("ymm")
    if is_ymm and operation == "pshufb":
        return None
    registers = tuple((_parse_ymm_operand if is_ymm else _parse_xmm_operand)(operand) for operand in operands)
    return (
        ("fppackedvex256" if is_ymm else "fppackedvex", operation, *registers)
        if not any(register is None for register in registers)
        else None
    )


def _decode_fp_vex_broadcast(text: str) -> tuple[str, str, int, int] | None:
    """Decode the two-register YMM qword broadcast form."""
    parts = text.split(None, 1)
    if len(parts) != _PART_COUNT or parts[0].lower() != "vpbroadcastq":
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _BROADCAST_OPERAND_COUNT:
        return None
    destination = _parse_ymm_operand(operands[0])
    source = _parse_xmm_operand(operands[1])
    if destination is None or source is None:
        return None
    return ("fpmovvex256", "broadcastq", destination, source)
