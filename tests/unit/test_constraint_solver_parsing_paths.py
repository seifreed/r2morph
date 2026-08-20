from __future__ import annotations

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver
from tests.utils.assertions import expect


def test_constraint_solver_parse_expression_ops() -> None:
    solver = ConstraintSolver(timeout=2)
    vars_map: dict[str, object] = {}

    expect(solver._parse_expression_to_z3("~x", vars_map) is not None)
    expect(solver._parse_expression_to_z3("+x", vars_map) is not None)
    expect(solver._parse_expression_to_z3("-x", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x + 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x & 3", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x | 3", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x ^ 3", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x << 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x >> 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x % 3", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x == 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x != 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x < 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x <= 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x > 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x >= 1", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x > 1 and x < 4", vars_map) is not None)
    expect(solver._parse_expression_to_z3("x == 1 or x == 2", vars_map) is not None)


def test_constraint_solver_statistics_paths() -> None:
    solver = ConstraintSolver(timeout=2)
    stats = solver.get_solver_statistics()
    expect(stats["queries_solved"] == 0)

    solver.solver_stats["queries_solved"] = 1
    solver.solver_stats["queries_timeout"] = 1
    stats = solver.get_solver_statistics()

    expect(not (stats["queries_solved"] < 1))
    expect(not (stats["success_rate"] < 0))
