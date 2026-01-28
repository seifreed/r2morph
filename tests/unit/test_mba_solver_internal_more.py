from r2morph.devirtualization.mba_solver import MBASolver, MBAComplexity


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
