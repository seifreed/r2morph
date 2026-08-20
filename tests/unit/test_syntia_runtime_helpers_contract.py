from r2morph.analysis.symbolic.syntia_runtime_helpers import (
    analyze_syntia_state,
    apply_mba_simplification_rules,
    evaluate_expression,
    synthesize_obfuscated_sequence,
)
from tests.utils.assertions import expect

_EXPECTED_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6 = 6
_EXPECTED_STATS_CACHE_HIT_RATE_0_5 = 0.5
_EXPECTED_STATS_CACHE_SIZE_3 = 3
_EXPECTED_STATS_SUCCESS_RATE_0_5 = 0.5


def test_syntia_runtime_helpers_contract() -> None:
    expect(apply_mba_simplification_rules("x ^ x", {"x"}) == "0")
    expect(evaluate_expression("x ^ y", {"x": 5, "y": 3}) == _EXPECTED_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6)
    expect(synthesize_obfuscated_sequence(["eax"], ["ebx"], "mov semantics") == ["mov ebx, eax"])

    stats = analyze_syntia_state(
        instructions_analyzed=2,
        semantics_learned=1,
        synthesis_failures=0,
        cache_hits=1,
        cache_size=3,
    )

    expect(stats["success_rate"] == _EXPECTED_STATS_SUCCESS_RATE_0_5)
    expect(stats["cache_hit_rate"] == _EXPECTED_STATS_CACHE_HIT_RATE_0_5)
    expect(stats["cache_size"] == _EXPECTED_STATS_CACHE_SIZE_3)
