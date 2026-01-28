from __future__ import annotations

from dataclasses import dataclass

import z3

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression


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

    assert result.satisfiable is True
    assert result.solver_used == "z3"
    assert result.model is not None
    assert "x" in result.model
    assert result.model["x"] > 1


def test_detect_opaque_predicates_true_false() -> None:
    solver = ConstraintSolver(timeout=2)
    x = z3.Int("x")
    constraints = [True, False, z3.BoolVal(True), z3.BoolVal(False), x > 0]

    predicates = solver.detect_opaque_predicates(constraints)

    assert any(item["always_true"] for item in predicates)
    assert any(item["always_false"] for item in predicates)


def test_simplify_mba_expression_xor_self() -> None:
    solver = ConstraintSolver(timeout=2)
    mba = MBAExpression(expression="x ^ x", variables={"x"}, bit_width=64)

    result = solver.simplify_mba_expression(mba)

    assert result.satisfiable is True
    assert result.simplified_expression is not None
    assert "0" in result.simplified_expression


def test_check_semantic_equivalence_basic() -> None:
    solver = ConstraintSolver(timeout=2)
    equivalent = solver.check_semantic_equivalence("x + 1", "1 + x", {"x"})
    not_equivalent = solver.check_semantic_equivalence("x + 1", "x + 2", {"x"})

    assert equivalent.satisfiable is True
    assert not_equivalent.satisfiable is False
