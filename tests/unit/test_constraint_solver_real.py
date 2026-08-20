import z3

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression
from tests.utils.assertions import expect


def test_constraint_solver_basic_path_solve():
    solver = ConstraintSolver(timeout=1)
    result = solver.solve_path_constraints([])

    expect(not (result.solver_used not in {"z3", "none"}))
    expect(not (result.solving_time < 0.0))

    stats = solver.get_solver_statistics()
    expect(not ("queries_solved" not in stats))
    expect(not ("queries_timeout" not in stats))


def test_constraint_solver_mba_simplification():
    solver = ConstraintSolver(timeout=1)
    mba = MBAExpression(expression="x", variables={"x"}, bit_width=32)

    result = solver.simplify_mba_expression(mba)
    expect(not (result.solver_used not in {"z3", "none"}))

    if result.solver_used == "z3":
        expect(result.satisfiable)
        expect(result.simplified_expression is not None)
        expect(0.0 <= result.confidence <= 1.0)


def test_constraint_solver_opaque_predicates_detection():
    solver = ConstraintSolver(timeout=1)
    constraints = [z3.BoolVal(True), z3.BoolVal(False)]

    opaque = solver.detect_opaque_predicates(constraints)
    expect(isinstance(opaque, list))


def test_constraint_solver_equivalence_short_circuit():
    solver = ConstraintSolver(timeout=1)
    result = solver.check_semantic_equivalence("x", "x", {"x"})

    expect(not (result.solver_used not in {"z3", "none"}))
    expect(not (result.solving_time < 0.0))
