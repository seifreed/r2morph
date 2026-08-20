from __future__ import annotations

from r2morph.devirtualization.mba_solver import MBAComplexity, MBASolver
from tests.utils.assertions import expect


def test_mba_solver_analysis_metrics_complexity() -> None:
    solver = MBASolver(timeout=1)
    expr = "(x + y) * (x ^ y) + (x & y)"

    analysis = solver.analyze_mba_expression(expr)

    expect(analysis.variables == {"x", "y"})
    expect(not (analysis.complexity not in {MBAComplexity.MEDIUM, MBAComplexity.COMPLEX}))
    expect(not (analysis.degree < 1))
    expect(not (analysis.coefficient_count < 0))


def test_mba_solver_auto_method_selection_truth_table() -> None:
    solver = MBASolver(timeout=1, max_variables=3)
    expr = "x ^ x"

    result = solver.simplify_mba(expr, method="auto")

    expect(result.method_used == "auto")
    expect(not (result.solving_time < 0.0))
