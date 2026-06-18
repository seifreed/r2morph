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
