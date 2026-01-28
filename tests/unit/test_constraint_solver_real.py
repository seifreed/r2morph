import z3

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression


def test_constraint_solver_basic_path_solve():
    solver = ConstraintSolver(timeout=1)
    result = solver.solve_path_constraints([])

    assert result.solver_used in {"z3", "none"}
    assert result.solving_time >= 0.0

    stats = solver.get_solver_statistics()
    assert "queries_solved" in stats
    assert "queries_timeout" in stats


def test_constraint_solver_mba_simplification():
    solver = ConstraintSolver(timeout=1)
    mba = MBAExpression(expression="x", variables={"x"}, bit_width=32)

    result = solver.simplify_mba_expression(mba)
    assert result.solver_used in {"z3", "none"}

    if result.solver_used == "z3":
        assert result.satisfiable
        assert result.simplified_expression is not None
        assert 0.0 <= result.confidence <= 1.0


def test_constraint_solver_opaque_predicates_detection():
    solver = ConstraintSolver(timeout=1)
    constraints = [z3.BoolVal(True), z3.BoolVal(False)]

    opaque = solver.detect_opaque_predicates(constraints)
    assert isinstance(opaque, list)


def test_constraint_solver_equivalence_short_circuit():
    solver = ConstraintSolver(timeout=1)
    result = solver.check_semantic_equivalence("x", "x", {"x"})

    assert result.solver_used in {"z3", "none"}
    assert result.solving_time >= 0.0
