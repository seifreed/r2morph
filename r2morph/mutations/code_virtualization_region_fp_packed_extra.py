"""Additional legacy packed-SIMD register decoders."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_fp_decoders import _parse_xmm_operand

_PACKED_OPERAND_COUNT = 2
_EXTRA_PACKED_ARITHMETIC = frozenset({"pcmpeqb", "pcmpgtb", "pminub"})


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


__all__ = ["_decode_fp_packed_arith_extra"]
