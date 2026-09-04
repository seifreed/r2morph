"""Locked memory-immediate decoding for region virtualization."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_memory_immediate

_LOCKED_IMMEDIATE_MNEMONICS = frozenset({"add", "sub", "and", "or", "xor"})
_LOCKED_INSTRUCTION_PART_COUNT = 3
_ATOMIC_IMMEDIATE_KINDS = {
    "storei": "atomicmemimm",
    "storeirip": "atomicmemimmrip",
    "storeiidx": "atomicmemimmidx",
    "storeiidxnb": "atomicmemimmidxnb",
}


def _decode_locked_memory_immediate(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode a locked immediate RMW by reusing the memory-immediate address contract."""
    parts = text.split(None, 2)
    if (
        len(parts) != _LOCKED_INSTRUCTION_PART_COUNT
        or parts[0].lower() != "lock"
        or parts[1].lower() not in _LOCKED_IMMEDIATE_MNEMONICS
    ):
        return None
    decoded = _decode_memory_immediate(f"mov {parts[2]}", insn_addr, insn_size)
    if decoded is None:
        return None
    return (_ATOMIC_IMMEDIATE_KINDS[decoded[0]], parts[1].lower(), *decoded[1:])
