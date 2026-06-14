from r2morph.analysis.symbolic.constraint_solver_models import ConstraintType, MBAExpression, SolverResult


def test_constraint_solver_models_contract() -> None:
    assert ConstraintType.PATH_CONSTRAINT.value == "path"

    mba = MBAExpression(expression="x ^ x", variables={"x"}, bit_width=32)
    assert mba.bit_width == 32
    assert mba.variables == {"x"}

    result = SolverResult(satisfiable=True, model={"x": 1}, solver_used="z3")
    assert result.satisfiable is True
    assert result.model == {"x": 1}
