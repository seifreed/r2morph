"""Regression: RelocationManager._update_data_ref must return False on
degenerate r2 output, not crash with AttributeError.

Pre-fix it did current_ptr_hex.strip() with no None/empty guard. r2.cmd
can return None (documented in core/reader.py), and None.strip()
raises AttributeError, which the surrounding
`except (ValueError, OSError, BrokenPipeError)` does NOT catch — so it
escaped and aborted the relocation update. Real double, no mocks.
"""

from __future__ import annotations

import pytest

from r2morph.relocations.manager import RelocationManager
from tests._doubles.scripted_r2_binary import ScriptedR2Binary


@pytest.mark.parametrize("p8_response", [None, ""])
def test_degenerate_pointer_read_returns_false_without_crash(p8_response: str | None) -> None:
    rm = RelocationManager(ScriptedR2Binary({"p8": p8_response}, arch_info={"bits": 64}))
    assert rm._update_data_ref(0x1000, 0xDEAD, 0xBEEF) is False


def test_matching_pointer_is_rewritten() -> None:
    # ptr_size=4; little-endian 0x11223344 -> "44332211".
    binary = ScriptedR2Binary({"p8": "44332211"}, arch_info={"bits": 32})
    rm = RelocationManager(binary)

    assert rm._update_data_ref(0x2000, 0x11223344, 0x55667788) is True
    assert binary.writes == [(0x2000, (0x55667788).to_bytes(4, "little"))]


def test_non_matching_pointer_is_left_untouched() -> None:
    binary = ScriptedR2Binary({"p8": "44332211"}, arch_info={"bits": 32})
    rm = RelocationManager(binary)

    assert rm._update_data_ref(0x2000, 0x99999999, 0x55667788) is False
    assert binary.writes == []
