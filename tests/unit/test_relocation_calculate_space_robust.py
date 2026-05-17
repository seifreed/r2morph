"""Regression: RelocationManager.calculate_space_needed must return
False on degenerate r2 output, not crash.

Pre-fix it ran json.loads(insn_json) and bytes.fromhex(
next_bytes_hex.strip()) with no guards, so transient r2 output
(empty/None/non-JSON/non-hex — documented under r2pipe load/BrokenPipe)
raised JSONDecodeError / TypeError / ValueError / AttributeError and
aborted the relocation operation. It also returned True for empty
next_bytes (all() over b"" is True). The method's own contract already
returns False on uncertainty (e.g. `if not insns`). Real double, no
mocks.
"""

from __future__ import annotations

import pytest

from r2morph.relocations.manager import RelocationManager
from tests._doubles.scripted_r2_binary import ScriptedR2Binary

VALID_AOJ = '[{"size": 4}]'


@pytest.mark.parametrize(
    "responses",
    [
        {"aoj": "", "p8": "90909090"},  # json.loads("") -> JSONDecodeError
        {"aoj": None, "p8": "90909090"},  # json.loads(None) -> TypeError
        {"aoj": "not json", "p8": "90909090"},  # JSONDecodeError
        {"aoj": VALID_AOJ, "p8": "zz"},  # bytes.fromhex("zz") -> ValueError
        {"aoj": VALID_AOJ, "p8": "abc"},  # odd-length hex -> ValueError
        {"aoj": VALID_AOJ, "p8": None},  # None.strip() -> AttributeError
        {"aoj": VALID_AOJ, "p8": ""},  # empty -> must be False, not all([])==True
    ],
)
def test_degenerate_r2_output_returns_false_without_crash(responses: dict[str, str | None]) -> None:
    rm = RelocationManager(ScriptedR2Binary(responses))
    assert rm.calculate_space_needed(0x1000, 8) is False


def test_real_nop_cave_still_reports_space_available() -> None:
    rm = RelocationManager(ScriptedR2Binary({"aoj": VALID_AOJ, "p8": "90909090"}))
    assert rm.calculate_space_needed(0x1000, 4) is True


def test_non_padding_bytes_still_report_no_space() -> None:
    rm = RelocationManager(ScriptedR2Binary({"aoj": VALID_AOJ, "p8": "0102feff"}))
    assert rm.calculate_space_needed(0x1000, 4) is False
