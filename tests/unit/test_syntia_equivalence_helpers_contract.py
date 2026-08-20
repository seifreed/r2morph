from r2morph.analysis.symbolic.syntia_equivalence_helpers import (
    check_mba_equivalence,
    normalize_expression,
    synthesis_equivalence_check,
)
from tests.utils.assertions import expect

_EXPECTED_CHECK_MBA_EQUIVALENCE_X_X_X_X_0_9 = 0.9


def test_syntia_equivalence_helpers_contract() -> None:
    expect(normalize_expression("  0x10 + X  ") == "16+x")
    expect(check_mba_equivalence("x+~x", "~x+x") == _EXPECTED_CHECK_MBA_EQUIVALENCE_X_X_X_X_0_9)

    def evaluator(expression: str, values: dict[str, int]) -> int:
        if expression == "x":
            return values["x"]
        if expression == "y":
            return values["y"]
        return values["x"] ^ values["y"]

    expect(synthesis_equivalence_check("x", "x", {"x"}, evaluator) == 1.0)
