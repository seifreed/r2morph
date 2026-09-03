"""Additional legacy packed-SIMD register decoders."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_decoders import _parse_mem_operand
from r2morph.mutations.code_virtualization_region_fp_decoders import _parse_xmm_operand
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _parse_indexed_operand,
    _parse_riprel_operand,
)

_PACKED_OPERAND_COUNT = 2
_EXTRA_PACKED_ARITHMETIC = frozenset({"pcmpeqb", "pcmpgtb", "pmaxub", "pminub", "pshufb"})


def _decode_fp_packed_arith_extra(text: str) -> tuple[str, str, int, int] | None:
    """Decode additional two-operand legacy packed integer operations."""
    parts = text.split(None, 1)
    if len(parts) != _PACKED_OPERAND_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _EXTRA_PACKED_ARITHMETIC:
        return None
    destination, source = (token.strip() for token in parts[1].split(",", 1))
    destination_index = _parse_xmm_operand(destination)
    source_index = _parse_xmm_operand(source)
    if destination_index is None or source_index is None:
        return None
    return ("fppacked", mnemonic, destination_index, source_index)


def _extra_memory_operands(text: str) -> tuple[str, int, str] | None:
    parts = text.split(None, 1)
    if len(parts) != _PACKED_OPERAND_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _EXTRA_PACKED_ARITHMETIC:
        return None
    destination, source = (token.strip() for token in parts[1].split(",", 1))
    destination_index = _parse_xmm_operand(destination)
    if destination_index is None or "[" not in source:
        return None
    return mnemonic, destination_index, source.lower().replace("xmmword", "")


def _decode_fp_packed_arith_extra_mem(text: str) -> tuple[str, str, int, int, int] | None:
    parsed = _extra_memory_operands(text)
    if parsed is None:
        return None
    mnemonic, destination, source = parsed
    memory = _parse_mem_operand(source)
    if memory is None:
        return None
    base, displacement, _width = memory
    return "fppackedmem", mnemonic, destination, base, displacement


def _decode_fp_packed_arith_extra_riprel(text: str, insn_addr: int, insn_size: int) -> tuple[str, str, int, int] | None:
    parsed = _extra_memory_operands(text)
    if parsed is None:
        return None
    mnemonic, destination, source = parsed
    target = _parse_riprel_operand(source, insn_addr, insn_size)
    if target is None:
        return None
    return "fppackedmemrip", mnemonic, destination, target[0]


def _decode_fp_packed_arith_extra_idx(
    text: str,
) -> tuple[str, str, int, int, int, int] | tuple[str, str, int, int, int, int, int] | None:
    parsed = _extra_memory_operands(text)
    if parsed is None:
        return None
    mnemonic, destination, source = parsed
    indexed = _parse_indexed_operand(source, base_optional=True)
    if indexed is None:
        return None
    base, index, shift, displacement = indexed
    if base < 0:
        return "fppackedmemidxnb", mnemonic, destination, index, shift, displacement
    return "fppackedmemidx", mnemonic, destination, base, index, shift, displacement


__all__ = [
    "_decode_fp_packed_arith_extra",
    "_decode_fp_packed_arith_extra_idx",
    "_decode_fp_packed_arith_extra_mem",
    "_decode_fp_packed_arith_extra_riprel",
]
