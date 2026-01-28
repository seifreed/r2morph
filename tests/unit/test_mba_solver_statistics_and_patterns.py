from r2morph.devirtualization.mba_solver import MBASolver


def test_mba_solver_pattern_optimize_complex_skips():
    solver = MBASolver(timeout=1)
    expr = "x + y * z - w"

    simplified = solver._simplify_with_patterns(expr)
    assert simplified is None


def test_mba_solver_statistics_after_simplification():
    solver = MBASolver(timeout=1)
    expr = "x + y - (x & y)"

    stats_before = solver.get_solver_statistics()
    assert stats_before["success_rate"] == 0.0
    assert stats_before["pattern_success_rate"] == 0.0

    result = solver.simplify_mba(expr, method="patterns")
    assert result.success is True

    stats_after = solver.get_solver_statistics()
    assert stats_after["expressions_analyzed"] >= 1
    assert stats_after["expressions_simplified"] >= 1
    assert stats_after["pattern_matches"] >= 1
    assert stats_after["success_rate"] > 0.0
