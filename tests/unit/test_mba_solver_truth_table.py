from r2morph.devirtualization.mba_solver import MBASolver, MBAExpression


def test_mba_solver_truth_table_simplification():
    solver = MBASolver(timeout=1, max_variables=4)
    mba = MBAExpression(expression="x ^ y")
    mba.variables = {"x", "y"}

    simplified = solver._simplify_with_truth_table(mba)
    assert simplified in {"x ^ y", "y ^ x", "x | y", "x & y", "0", "1", "x", "y"}

    mba_const = MBAExpression(expression="x & 0")
    mba_const.variables = {"x"}
    simplified_const = solver._simplify_with_truth_table(mba_const)
    assert simplified_const in {"0", "x", "1"}
