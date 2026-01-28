from r2morph.devirtualization.mba_solver import MBASolver


def test_mba_pattern_based_simplification():
    solver = MBASolver()
    expr = "x + y - (x & y)"
    analysis = solver.analyze_mba_expression(expr)

    assert "x" in analysis.variables
    assert analysis.is_linear is True

    result = solver.simplify_mba(expr, method="patterns")
    assert result.success is True
    assert result.simplified_expression is not None
    assert result.original_expression == expr


def test_mba_z3_simplification():
    solver = MBASolver()
    expr = "x + 0"
    result = solver.simplify_mba(expr, method="z3")

    assert result.success is True
    assert result.simplified_expression in {"x", "x + 0"} or result.simplified_expression is not None


def test_mba_truth_table_simplification():
    solver = MBASolver()
    expr = "x & x"
    result = solver.simplify_mba(expr, method="truth_table")

    assert result.success is True
    assert result.simplified_expression == "x"
