"""Regression: RelocationManager._update_control_flow_ref and
shift_code_block must return False on None r2 output, not crash.

Same class as iter-11/12. r2.cmd can return None (documented in
core/reader.py):
  - _update_control_flow_ref: json.loads(None) raises TypeError, which
    its `except (ValueError, OSError, BrokenPipeError, JSONDecodeError)`
    does NOT catch -> escaped.
  - shift_code_block: None.strip() raises AttributeError, which its
    `except (ValueError, OSError, BrokenPipeError)` does NOT catch.
Real double, no mocks.
"""

from __future__ import annotations

from r2morph.relocations.manager import RelocationManager
from tests._doubles.scripted_r2_binary import ScriptedR2Binary
from tests.utils.assertions import expect


def test_update_control_flow_ref_none_insn_returns_false() -> None:
    rm = RelocationManager(ScriptedR2Binary({"aoj": None}))
    expect(not (rm._update_control_flow_ref(0x1000, 0xDEAD, 0xBEEF, "call") is not False))


def test_shift_code_block_none_read_returns_false() -> None:
    rm = RelocationManager(ScriptedR2Binary({"p8": None}))
    expect(not (rm.shift_code_block(0x1000, 16, 8) is not False))


def test_shift_code_block_valid_read_still_shifts() -> None:
    binary = ScriptedR2Binary({"p8": "90909090"})
    rm = RelocationManager(binary)

    # shift_amount < 0 -> no nop_fill path; pure read + write + relocate.
    expect(not (rm.shift_code_block(0x1000, 4, -4) is not True))
    expect(binary.writes == [(4092, b"\x90\x90\x90\x90")])
