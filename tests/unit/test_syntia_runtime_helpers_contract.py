from r2morph.analysis.symbolic.syntia_runtime_helpers import (
    analyze_syntia_state,
    apply_mba_simplification_rules,
    evaluate_expression,
    synthesize_obfuscated_sequence,
)


def test_syntia_runtime_helpers_contract() -> None:
    assert apply_mba_simplification_rules("x ^ x", {"x"}) == "0"
    assert evaluate_expression("x ^ y", {"x": 5, "y": 3}) == 6
    assert synthesize_obfuscated_sequence(["eax"], ["ebx"], "mov semantics") == ["mov ebx, eax"]

    stats = analyze_syntia_state(
        instructions_analyzed=2,
        semantics_learned=1,
        synthesis_failures=0,
        cache_hits=1,
        cache_size=3,
    )

    assert stats["success_rate"] == 0.5
    assert stats["cache_hit_rate"] == 0.5
    assert stats["cache_size"] == 3
