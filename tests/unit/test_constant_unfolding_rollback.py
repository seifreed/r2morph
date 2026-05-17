"""Regression tests for ConstantUnfoldingPass._apply_single_unfold.

Covers two bugs in the pre-fix code:

1. ``original_bytes`` (and the rollback checkpoint) were captured *after*
   ``write_bytes``/``nop_fill``, so the recorded "original" was actually a
   copy of the already-mutated bytes — the recorded diff was inert and the
   restore target was the mutated state, not the real original.

2. The ``nop_fill`` return value was ignored. When a shorter replacement was
   written but the trailing gap could not be NOP-filled, the stale tail of
   the original instruction was left in place and the mutation was still
   recorded as successful, corrupting the binary instead of rolling back.

Both are exercised through a real in-memory binary double (no mocks).
"""

from __future__ import annotations

from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from tests._doubles.in_memory_unfold_binary import InMemoryUnfoldBinary

BASE_ADDR = 0x1000
# 5-byte "mov eax, 42" (b8 2a 00 00 00) replaced by 2-byte "xor eax, eax".
ORIGINAL = b"\xb8\x2a\x00\x00\x00"
ASSEMBLED = b"\x31\xc0"
ORIG_SIZE = len(ORIGINAL)
FUNC = {"addr": BASE_ADDR}


def _apply(binary: InMemoryUnfoldBinary) -> tuple[bool, ConstantUnfoldingPass]:
    pass_ = ConstantUnfoldingPass()
    applied = pass_._apply_single_unfold(
        binary,
        FUNC,
        BASE_ADDR,
        ORIG_SIZE,
        "mov eax, 42",
        ["xor eax, eax"],
        {},
    )
    return applied, pass_


def test_recorded_original_is_pre_write_bytes_not_mutated_copy() -> None:
    """The recorded original must be the bytes before the write, not after."""
    binary = InMemoryUnfoldBinary(
        base_addr=BASE_ADDR,
        contents=ORIGINAL,
        assembled=ASSEMBLED,
        nop_fill_succeeds=True,
    )

    applied, pass_ = _apply(binary)

    assert applied is True
    record = pass_.get_records()[-1]
    assert record.original_bytes == ORIGINAL.hex()
    assert record.mutated_bytes == (ASSEMBLED + b"\x90\x90\x90").hex()
    assert record.original_bytes != record.mutated_bytes


def test_failed_nop_fill_rolls_back_and_is_not_recorded() -> None:
    """A failed NOP fill must roll back, return False, and record nothing."""
    binary = InMemoryUnfoldBinary(
        base_addr=BASE_ADDR,
        contents=ORIGINAL,
        assembled=ASSEMBLED,
        nop_fill_succeeds=False,
    )

    applied, pass_ = _apply(binary)

    assert applied is False
    assert pass_.get_records() == []
    assert binary.reload_called is True
