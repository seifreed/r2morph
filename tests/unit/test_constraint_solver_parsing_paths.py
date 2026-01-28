from __future__ import annotations

import z3

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver


def test_constraint_solver_parse_expression_ops() -> None:
    solver = ConstraintSolver(timeout=2)
    vars_map: dict[str, object] = {}

    assert solver._parse_expression_to_z3("~x", vars_map) is not None
    assert solver._parse_expression_to_z3("+x", vars_map) is not None
    assert solver._parse_expression_to_z3("-x", vars_map) is not None
    assert solver._parse_expression_to_z3("x + 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x & 3", vars_map) is not None
    assert solver._parse_expression_to_z3("x | 3", vars_map) is not None
    assert solver._parse_expression_to_z3("x ^ 3", vars_map) is not None
    assert solver._parse_expression_to_z3("x << 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x >> 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x % 3", vars_map) is not None
    assert solver._parse_expression_to_z3("x == 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x != 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x < 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x <= 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x > 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x >= 1", vars_map) is not None
    assert solver._parse_expression_to_z3("x > 1 and x < 4", vars_map) is not None
    assert solver._parse_expression_to_z3("x == 1 or x == 2", vars_map) is not None


def test_constraint_solver_statistics_paths() -> None:
    solver = ConstraintSolver(timeout=2)
    stats = solver.get_solver_statistics()
    assert stats["queries_solved"] == 0

    solver.solver_stats["queries_solved"] = 1
    solver.solver_stats["queries_timeout"] = 1
    stats = solver.get_solver_statistics()

    assert stats["queries_solved"] >= 1
    assert stats["success_rate"] >= 0
