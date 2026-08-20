from __future__ import annotations

from r2morph.analysis.symbolic.structural_resistance import _dispatch_score


def test_dispatch_score_excludes_raw_instruction_count() -> None:
    assert _dispatch_score(3, 4) == 38.0
