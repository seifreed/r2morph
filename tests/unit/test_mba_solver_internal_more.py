from r2morph.devirtualization.mba_solver import MBAComplexity, MBASolver
from tests.utils.assertions import expect

_EXPECTED_SOLVER_CALCULATE_PARENTHESES_DEPTH_X_2 = 2
_EXPECTED_SOLVER_COUNT_COEFFICIENTS_2_X_3_Y_5_3 = 3
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_X_5_NEG__5 = -5
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_16_Y_2_4 = 4
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_1_Y_4_16 = 16
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_2_Y_3_5 = 5
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_4_Y_1_5 = 5
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_4_Y_3_12 = 12
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6 = 6
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_6_Y_3_2 = 2
_EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_7_Y_4_3 = 3


def test_mba_solver_internal_helpers():
    solver = MBASolver(timeout=1)

    variables = solver._extract_variables("x + y ^ z1")
    expect(variables == {"x", "y", "z1"})

    complexity = solver._assess_complexity("x + y")
    expect(not (complexity not in {MBAComplexity.SIMPLE, MBAComplexity.MEDIUM, MBAComplexity.COMPLEX}))

    expect(solver._calculate_parentheses_depth("((x))") == _EXPECTED_SOLVER_CALCULATE_PARENTHESES_DEPTH_X_2)
    expect(not (solver._is_linear_mba("x + y + 1") is not True))
    expect(not (solver._calculate_polynomial_degree("x*y + x") < 1))
    expect(solver._count_coefficients("2*x + 3*y - 5") == _EXPECTED_SOLVER_COUNT_COEFFICIENTS_2_X_3_Y_5_3)

    cleaned = solver._cleanup_z3_output("BitVecVal(1)#64")
    expect("BitVec" not in cleaned)

    expect(solver._evaluate_expression("x & y", {"x": 1, "y": 0}) == 0)

    truth_table = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
    simplified = solver._find_simple_equivalent(truth_table, ["x", "y"])
    expect(simplified == "x ^ y")

    reduction = solver._calculate_complexity_reduction("x + x", "x")
    expect(0.0 <= reduction <= 1.0)

    expect(solver._generate_native_equivalent("x ^ y") == "xor eax, ebx")


def test_safe_eval_node_all_operators():
    """Characterize every binary/unary operator path of _safe_eval_node
    (oracle for hoisting its operator tables to module scope)."""
    solver = MBASolver(timeout=1)

    expect(solver._evaluate_expression("x & y", {"x": 6, "y": 3}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_6_Y_3_2)
    expect(solver._evaluate_expression("x | y", {"x": 4, "y": 1}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_4_Y_1_5)
    expect(solver._evaluate_expression("x ^ y", {"x": 5, "y": 3}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6)
    expect(solver._evaluate_expression("x + y", {"x": 2, "y": 3}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_2_Y_3_5)
    expect(solver._evaluate_expression("x - y", {"x": 7, "y": 4}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_7_Y_4_3)
    expect(
        solver._evaluate_expression("x * y", {"x": 4, "y": 3}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_4_Y_3_12
    )
    expect(
        solver._evaluate_expression("x << y", {"x": 1, "y": 4}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_1_Y_4_16
    )
    expect(
        solver._evaluate_expression("x >> y", {"x": 16, "y": 2}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_Y_X_16_Y_2_4
    )
    expect(solver._evaluate_expression("-x", {"x": 5}) == _EXPECTED_SOLVER_EVALUATE_EXPRESSION_X_X_5_NEG__5)
    expect(solver._evaluate_expression("~x", {"x": 0}) == -1)
