from __future__ import annotations

from r2morph.devirtualization.mba_solver import MBASolver, MBAComplexity


def test_mba_solver_analysis_metrics_complexity() -> None:
    solver = MBASolver(timeout=1)
    expr = "(x + y) * (x ^ y) + (x & y)"

    analysis = solver.analyze_mba_expression(expr)

    assert analysis.variables == {"x", "y"}
    assert analysis.complexity in {MBAComplexity.MEDIUM, MBAComplexity.COMPLEX}
    assert analysis.degree >= 1
    assert analysis.coefficient_count >= 0


def test_mba_solver_auto_method_selection_truth_table() -> None:
    solver = MBASolver(timeout=1, max_variables=3)
    expr = "x ^ x"

    result = solver.simplify_mba(expr, method="auto")

    assert result.method_used == "auto"
    assert result.solving_time >= 0.0
