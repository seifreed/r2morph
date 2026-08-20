from r2morph.devirtualization.mba_solver import MBASolver
from tests.utils.assertions import expect


def test_mba_solver_pattern_optimize_complex_skips():
    solver = MBASolver(timeout=1)
    expr = "x + y * z - w"

    simplified = solver._simplify_with_patterns(expr)
    expect(not (simplified is not None))


def test_mba_solver_statistics_after_simplification():
    solver = MBASolver(timeout=1)
    expr = "x + y - (x & y)"

    stats_before = solver.get_solver_statistics()
    expect(stats_before["success_rate"] == 0.0)
    expect(stats_before["pattern_success_rate"] == 0.0)

    result = solver.simplify_mba(expr, method="patterns")
    expect(not (result.success is not True))

    stats_after = solver.get_solver_statistics()
    expect(not (stats_after["expressions_analyzed"] < 1))
    expect(not (stats_after["expressions_simplified"] < 1))
    expect(not (stats_after["pattern_matches"] < 1))
    expect(not (stats_after["success_rate"] <= 0.0))
