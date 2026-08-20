from r2morph.analysis.symbolic.constraint_solver_conversions import (
    convert_angr_to_z3,
    convert_single_constraint,
    extract_model,
)
from tests.utils.assertions import expect


class _Constraint:
    def to_z3(self) -> str:
        return "converted"


def test_constraint_solver_conversions_contract() -> None:
    expect(convert_angr_to_z3([_Constraint(), object()], None) == [])
    expect(not (convert_single_constraint(True, None) is not None))

    model = extract_model(None, None)
    expect(model == {})
