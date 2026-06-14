from r2morph.analysis.symbolic.syntia_equivalence_helpers import (
    check_mba_equivalence,
    normalize_expression,
    synthesis_equivalence_check,
)


def test_syntia_equivalence_helpers_contract() -> None:
    assert normalize_expression("  0x10 + X  ") == "16+x"
    assert check_mba_equivalence("x+~x", "~x+x") == 0.9

    def evaluator(expression: str, values: dict[str, int]) -> int:
        if expression == "x":
            return values["x"]
        if expression == "y":
            return values["y"]
        return values["x"] ^ values["y"]

    assert synthesis_equivalence_check("x", "x", {"x"}, evaluator) == 1.0
