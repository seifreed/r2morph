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


def test_mba_solver_helpers_contract() -> None:
    patterns = load_mba_patterns()
    assert patterns
    assert extract_variables("x + y ^ z1") == {"x", "y", "z1"}
    assert assess_complexity("x + y") == "simple"
    assert calculate_parentheses_depth("((x))") == 2
    assert is_linear_mba("x + y + 1") is True
    assert calculate_polynomial_degree("x*y + x") >= 1
    assert count_coefficients("2*x + 3*y - 5") == 3
    assert cleanup_z3_output("BitVecVal(1)#64") == "(1)"
    assert evaluate_expression("x & y", {"x": 1, "y": 0}) == 0
    truth_table = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
    assert find_simple_equivalent(truth_table, ["x", "y"]) == "x ^ y"
    assert 0.0 <= calculate_complexity_reduction("x + x", "x") <= 1.0
    assert generate_native_equivalent("x ^ y") == "xor eax, ebx"
