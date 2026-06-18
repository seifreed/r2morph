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

import random

# (field name, byte size). The opcode is implicit at offset 0; these are operands.
Field = tuple[str, int]


def _op_operand_fields(handler_key: str) -> list[Field]:
    # "op_<mnemonic>_<mode>_<width>" / "opmba_..." - immediate form carries the
    # destination slot plus a width/8-byte immediate; register form two slots.
    _kind, _mnemonic, mode, width_text = handler_key.split("_")
    if mode == "i":
        return [("dst", 1), ("imm", int(width_text) // 8)]
    return [("dst", 1), ("src", 1)]


# Item-kind prefix -> builder for its canonical operand field list. Kinds absent
# here keep the legacy fixed layout (added incrementally as they are converted).
_OPERAND_FIELDS = {
    "op": _op_operand_fields,
    "opmba": _op_operand_fields,
}


def has_layout(handler_key: str) -> bool:
    """Whether this handler key's item has a declarative (permutable) layout."""
    return handler_key.split("_", 1)[0] in _OPERAND_FIELDS


def permuted_fields(handler_key: str, field_perm: int) -> list[Field]:
    """The item's operand fields in this build's order (identity when 0)."""
    fields = _OPERAND_FIELDS[handler_key.split("_", 1)[0]](handler_key)
    if field_perm:
        random.Random(field_perm).shuffle(fields)
    return fields


def field_offsets(handler_key: str, field_perm: int) -> dict[str, int]:
    """Byte offset of each operand field for this build (opcode occupies 0)."""
    offsets: dict[str, int] = {}
    cursor = 1
    for name, size in permuted_fields(handler_key, field_perm):
        offsets[name] = cursor
        cursor += size
    return offsets
