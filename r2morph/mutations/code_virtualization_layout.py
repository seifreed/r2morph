"""
Per-build operand field layout for the region VM bytecode (polymorphic ISA).

Every VM item is one opcode byte at offset 0 followed by its operand fields. The
canonical layout puts those fields in a fixed order at fixed offsets, so a
devirtualizer that recovers one sample's layout (dst slot at ``[rsi+1]``, source
or immediate at ``[rsi+2]``, ...) reuses that model on every other sample.

This module is the single source of truth for the field order, so the encoder
(which emits the bytes) and the handlers (which read them) always agree. A
non-zero ``field_perm`` seed permutes each item's operand fields deterministically
per build, so two builds lay the same item out in different orders at different
offsets - a structurally distinct ISA - while the opcode stays at offset 0 and
the item's total size is unchanged (the same fields, reordered). ``field_perm``
0 is the identity layout (byte-identical to the pre-feature encoding).

The cipher is untouched: each operand byte is still position+key XOR-masked, and
multi-byte immediates still use the 32-bit broadcast decode, so reordering moves
only the byte offsets, never how a byte is decrypted.
"""

from __future__ import annotations

import r2morph.core.randomness as random

# (field name, byte size). The opcode is implicit at offset 0; these are operands.
Field = tuple[str, int]


def _op_fields(is_immediate: bool, width: int) -> list[Field]:
    # Immediate form carries the destination slot plus a width/8-byte immediate;
    # register form carries two slots.
    if is_immediate:
        return [("dst", 1), ("imm", width // 8)]
    return [("dst", 1), ("src", 1)]


def _op_operand_fields(handler_key: str) -> list[Field]:
    # "op_<mnemonic>_<mode>_<width>" / "opmba_..." (region's string handler key).
    _kind, _mnemonic, mode, width_text = handler_key.split("_")
    return _op_fields(mode == "i", int(width_text))


def op_permuted_fields(is_immediate: bool, width: int, field_perm: int) -> list[Field]:
    """Arith/mov operand fields in this build's order, keyed by (immediate, width).

    The engine keys handlers by ``(is_immediate, width)`` rather than a string, so
    it uses this directly; the region's string-key wrappers share the same core.
    """
    return _permute(_op_fields(is_immediate, width), field_perm)


def op_offsets(is_immediate: bool, width: int, field_perm: int) -> dict[str, int]:
    """Byte offset of each arith/mov operand field for this build."""
    return _offsets(op_permuted_fields(is_immediate, width, field_perm))


# Item-kind prefix -> builder for its canonical operand field list. Kinds absent
# here keep the legacy fixed layout (added incrementally as they are converted).
_OPERAND_FIELDS = {
    "op": _op_operand_fields,
    "opmba": _op_operand_fields,
    "opsynth": _op_operand_fields,
}


def has_layout(handler_key: str) -> bool:
    """Whether this handler key's item has a declarative (permutable) layout."""
    return handler_key.split("_", 1)[0] in _OPERAND_FIELDS


def _permute(fields: list[Field], field_perm: int) -> list[Field]:
    if field_perm:
        random.Random(field_perm).shuffle(fields)
    return fields


def _offsets(fields: list[Field]) -> dict[str, int]:
    offsets: dict[str, int] = {}
    cursor = 1  # operand bytes follow the 1-byte opcode at offset 0
    for name, size in fields:
        offsets[name] = cursor
        cursor += size
    return offsets


def permuted_fields(handler_key: str, field_perm: int) -> list[Field]:
    """The item's operand fields in this build's order (identity when 0)."""
    return _permute(_OPERAND_FIELDS[handler_key.split("_", 1)[0]](handler_key), field_perm)


def field_offsets(handler_key: str, field_perm: int) -> dict[str, int]:
    """Byte offset of each operand field for this build (opcode occupies 0)."""
    return _offsets(permuted_fields(handler_key, field_perm))


def pair_permuted_fields(first: str, second: str, field_perm: int) -> list[Field]:
    """Two single-byte operand fields in this build's order (identity when 0).

    Used by the scalar/packed FP register handlers, whose items carry exactly two
    one-byte operand fields (two xmm indices, or an xmm index and a GP slot); a
    non-zero ``field_perm`` swaps their order so the layout is not a fixed
    cross-sample signature.
    """
    return _permute([(first, 1), (second, 1)], field_perm)


def pair_offsets(first: str, second: str, field_perm: int) -> dict[str, int]:
    """Byte offset of each of two single-byte operand fields for this build."""
    return _offsets(pair_permuted_fields(first, second, field_perm))


def triple_permuted_fields(first: str, second: str, third: str, field_perm: int) -> list[Field]:
    """Three single-byte operand fields in this build's order."""
    return _permute([(first, 1), (second, 1), (third, 1)], field_perm)


def triple_offsets(first: str, second: str, third: str, field_perm: int) -> dict[str, int]:
    """Byte offsets for three single-byte operand fields."""
    return _offsets(triple_permuted_fields(first, second, third, field_perm))


def _mem_fields(riprel: bool) -> list[Field]:
    # Memory items shared by every handler that routes through the address
    # prologue: a register slot, the displacement, and (non-rip-relative) a base
    # slot. The rip-relative form stores its target as a 4-byte displacement only.
    if riprel:
        return [("reg", 1), ("disp", 4)]
    return [("reg", 1), ("base", 1), ("disp", 4)]


def mem_permuted_fields(riprel: bool, field_perm: int) -> list[Field]:
    """Memory item operand fields in this build's order (identity when 0)."""
    return _permute(_mem_fields(riprel), field_perm)


def mem_offsets(riprel: bool, field_perm: int) -> dict[str, int]:
    """Byte offset of each memory operand field for this build."""
    return _offsets(mem_permuted_fields(riprel, field_perm))


def shift_permuted_fields(field_perm: int) -> list[Field]:
    """Shift operand fields (slot, count) in this build's order."""
    return _permute([("slot", 1), ("count", 1)], field_perm)


def shift_offsets(field_perm: int) -> dict[str, int]:
    """Byte offset of each shift operand field for this build."""
    return _offsets(shift_permuted_fields(field_perm))


def imul3_permuted_fields(field_perm: int) -> list[Field]:
    """Three-operand imul fields (dst, src, 4-byte immediate) in this build's order."""
    return _permute([("dst", 1), ("src", 1), ("imm", 4)], field_perm)


def imul3_offsets(field_perm: int) -> dict[str, int]:
    """Byte offset of each three-operand imul field for this build."""
    return _offsets(imul3_permuted_fields(field_perm))


def _idx_fields(nobase: bool) -> list[Field]:
    # Scaled-index items: register slot, (optional) base slot, index slot, scale
    # shift, displacement. The no-base form (lea [index*scale+disp]) omits base.
    # Five fields give up to 120 orders - the richest per-build distinctness.
    if nobase:
        return [("reg", 1), ("index", 1), ("shift", 1), ("disp", 4)]
    return [("reg", 1), ("base", 1), ("index", 1), ("shift", 1), ("disp", 4)]


def idx_permuted_fields(nobase: bool, field_perm: int) -> list[Field]:
    """Scaled-index item operand fields in this build's order (identity when 0)."""
    return _permute(_idx_fields(nobase), field_perm)


def idx_offsets(nobase: bool, field_perm: int) -> dict[str, int]:
    """Byte offset of each scaled-index operand field for this build."""
    return _offsets(idx_permuted_fields(nobase, field_perm))
