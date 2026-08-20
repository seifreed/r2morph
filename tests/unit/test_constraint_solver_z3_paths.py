from __future__ import annotations

from dataclasses import dataclass

import z3

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression
from tests.utils.assertions import expect


@dataclass
class _Z3ConstraintWrapper:
    constraint: z3.ExprRef

    def to_z3(self) -> z3.ExprRef:
        return self.constraint


def test_solve_path_constraints_satisfiable() -> None:
    solver = ConstraintSolver(timeout=2)
    x = z3.Int("x")
    wrapper = _Z3ConstraintWrapper(x > 1)

    result = solver.solve_path_constraints([wrapper])

    expect(not (result.satisfiable is not True))
    expect(result.solver_used == "z3")
    expect(result.model is not None)
    expect(not ("x" not in result.model))
    expect(not (result.model["x"] <= 1))


def test_detect_opaque_predicates_true_false() -> None:
    solver = ConstraintSolver(timeout=2)
    x = z3.Int("x")
    constraints = [True, False, z3.BoolVal(True), z3.BoolVal(False), x > 0]

    predicates = solver.detect_opaque_predicates(constraints)

    expect(any(item["always_true"] for item in predicates))
    expect(any(item["always_false"] for item in predicates))


def test_simplify_mba_expression_xor_self() -> None:
    solver = ConstraintSolver(timeout=2)
    mba = MBAExpression(expression="x ^ x", variables={"x"}, bit_width=64)

    result = solver.simplify_mba_expression(mba)

    expect(not (result.satisfiable is not True))
    expect(result.simplified_expression is not None)
    expect(not ("0" not in result.simplified_expression))


def test_check_semantic_equivalence_basic() -> None:
    solver = ConstraintSolver(timeout=2)
    equivalent = solver.check_semantic_equivalence("x + 1", "1 + x", {"x"})
    not_equivalent = solver.check_semantic_equivalence("x + 1", "x + 2", {"x"})

    expect(not (equivalent.satisfiable is not True))
    expect(not (not_equivalent.satisfiable is not False))
