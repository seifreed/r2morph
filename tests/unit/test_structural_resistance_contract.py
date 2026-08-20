from __future__ import annotations

from r2morph.analysis.symbolic.structural_resistance import _dispatch_score
from tests.utils.assertions import expect

_EXPECTED_DISPATCH_SCORE_3_4_38_0 = 38.0


def test_dispatch_score_excludes_raw_instruction_count() -> None:
    expect(_dispatch_score(3, 4) == _EXPECTED_DISPATCH_SCORE_3_4_38_0)
