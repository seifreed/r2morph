from r2morph.devirtualization.mba_solver_helpers import (
    assess_complexity,
    calculate_complexity_reduction,
    calculate_parentheses_depth,
    calculate_polynomial_degree,
    cleanup_z3_output,
    count_coefficients,
    evaluate_expression,
    extract_variables,
    find_simple_equivalent,
    generate_native_equivalent,
    is_linear_mba,
    load_mba_patterns,
)
from tests.utils.assertions import expect

_EXPECTED_CALCULATE_PARENTHESES_DEPTH_X_2 = 2
_EXPECTED_COUNT_COEFFICIENTS_2_X_3_Y_5_3 = 3


def test_mba_solver_helpers_contract() -> None:
    patterns = load_mba_patterns()
    expect(patterns)
    expect(extract_variables("x + y ^ z1") == {"x", "y", "z1"})
    expect(assess_complexity("x + y") == "simple")
    expect(calculate_parentheses_depth("((x))") == _EXPECTED_CALCULATE_PARENTHESES_DEPTH_X_2)
    expect(not (is_linear_mba("x + y + 1") is not True))
    expect(not (calculate_polynomial_degree("x*y + x") < 1))
    expect(count_coefficients("2*x + 3*y - 5") == _EXPECTED_COUNT_COEFFICIENTS_2_X_3_Y_5_3)
    expect(cleanup_z3_output("BitVecVal(1)#64") == "(1)")
    expect(evaluate_expression("x & y", {"x": 1, "y": 0}) == 0)
    truth_table = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
    expect(find_simple_equivalent(truth_table, ["x", "y"]) == "x ^ y")
    expect(0.0 <= calculate_complexity_reduction("x + x", "x") <= 1.0)
    expect(generate_native_equivalent("x ^ y") == "xor eax, ebx")
