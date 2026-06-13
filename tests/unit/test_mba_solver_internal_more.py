from r2morph.devirtualization.mba_solver import MBAComplexity, MBASolver


def test_mba_solver_internal_helpers():
    solver = MBASolver(timeout=1)

    variables = solver._extract_variables("x + y ^ z1")
    assert variables == {"x", "y", "z1"}

    complexity = solver._assess_complexity("x + y")
    assert complexity in {MBAComplexity.SIMPLE, MBAComplexity.MEDIUM, MBAComplexity.COMPLEX}

    assert solver._calculate_parentheses_depth("((x))") == 2
    assert solver._is_linear_mba("x + y + 1") is True
    assert solver._calculate_polynomial_degree("x*y + x") >= 1
    assert solver._count_coefficients("2*x + 3*y - 5") == 3

    cleaned = solver._cleanup_z3_output("BitVecVal(1)#64")
    assert "BitVec" not in cleaned

    assert solver._evaluate_expression("x & y", {"x": 1, "y": 0}) == 0

    truth_table = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
    simplified = solver._find_simple_equivalent(truth_table, ["x", "y"])
    assert simplified == "x ^ y"

    reduction = solver._calculate_complexity_reduction("x + x", "x")
    assert 0.0 <= reduction <= 1.0

    assert solver._generate_native_equivalent("x ^ y") == "xor eax, ebx"


def test_safe_eval_node_all_operators():
    """Characterize every binary/unary operator path of _safe_eval_node
    (oracle for hoisting its operator tables to module scope)."""
    solver = MBASolver(timeout=1)

    assert solver._evaluate_expression("x & y", {"x": 6, "y": 3}) == 2
    assert solver._evaluate_expression("x | y", {"x": 4, "y": 1}) == 5
    assert solver._evaluate_expression("x ^ y", {"x": 5, "y": 3}) == 6
    assert solver._evaluate_expression("x + y", {"x": 2, "y": 3}) == 5
    assert solver._evaluate_expression("x - y", {"x": 7, "y": 4}) == 3
    assert solver._evaluate_expression("x * y", {"x": 4, "y": 3}) == 12
    assert solver._evaluate_expression("x << y", {"x": 1, "y": 4}) == 16
    assert solver._evaluate_expression("x >> y", {"x": 16, "y": 2}) == 4
    assert solver._evaluate_expression("-x", {"x": 5}) == -5
    assert solver._evaluate_expression("~x", {"x": 0}) == -1
