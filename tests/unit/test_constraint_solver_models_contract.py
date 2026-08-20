from r2morph.analysis.symbolic.constraint_solver_models import ConstraintType, MBAExpression, SolverResult
from tests.utils.assertions import expect

_EXPECTED_MBA_BIT_WIDTH_32 = 32


def test_constraint_solver_models_contract() -> None:
    expect(ConstraintType.PATH_CONSTRAINT.value == "path")

    mba = MBAExpression(expression="x ^ x", variables={"x"}, bit_width=32)
    expect(mba.bit_width == _EXPECTED_MBA_BIT_WIDTH_32)
    expect(mba.variables == {"x"})

    result = SolverResult(satisfiable=True, model={"x": 1}, solver_used="z3")
    expect(not (result.satisfiable is not True))
    expect(result.model == {"x": 1})
