import pytest

from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression
from r2morph.analysis.symbolic.constraint_solver_analysis import (
    SemanticEquivalenceQuery,
    check_semantic_equivalence,
    detect_opaque_predicates,
    simplify_mba_expression,
)

z3 = pytest.importorskip("z3")


def test_constraint_solver_analysis_contract() -> None:
    solver = ConstraintSolver(timeout=1)

    opaque = detect_opaque_predicates([z3.BoolVal(True), z3.BoolVal(False)], z3, lambda constraint: constraint)
    assert len(opaque) == 2
    assert opaque[0]["always_true"] is True
    assert opaque[1]["always_false"] is True

    mba = MBAExpression(expression="x", variables={"x"}, bit_width=32)
    mba_result = simplify_mba_expression(mba, z3, solver._parse_mba_to_z3)
    assert mba_result.solver_used == "z3"
    assert mba_result.satisfiable is True
    assert mba_result.simplified_expression == "x"

    equivalent = check_semantic_equivalence(
        SemanticEquivalenceQuery("x + 1", "1 + x", {"x"}),
        z3,
        solver._parse_expression_to_z3,
        1,
    )
    assert equivalent.solver_used == "z3"
    assert equivalent.satisfiable is True
