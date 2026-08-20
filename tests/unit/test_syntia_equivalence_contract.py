from r2morph.analysis.symbolic.syntia_equivalence import check_semantic_equivalence
from tests.utils.assertions import expect

_EXPECTED_CHECK_SEMANTIC_EQUIVALENCE_X_X_X_X_EVALUATE_E_0_9 = 0.9


def _evaluate_expression(expression: str, values: dict[str, int]) -> int | None:
    if expression == "x+x":
        return values["x"] + values["x"]
    if expression == "2*x":
        return values["x"] * 2
    if expression == "x|x":
        return values["x"]
    return None


def test_syntia_equivalence_contract_normalized_match() -> None:
    expect(check_semantic_equivalence("X + X", "x+x", {"x"}, _evaluate_expression) == 1.0)


def test_syntia_equivalence_contract_known_mba_equivalence() -> None:
    expect(
        check_semantic_equivalence("x|x", "x", {"x"}, _evaluate_expression)
        == _EXPECTED_CHECK_SEMANTIC_EQUIVALENCE_X_X_X_X_EVALUATE_E_0_9
    )


def test_syntia_equivalence_contract_falls_back_to_sampling() -> None:
    expect(check_semantic_equivalence("x+x", "2*x", {"x"}, _evaluate_expression) == 1.0)
