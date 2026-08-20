from r2morph.analysis.symbolic import constraint_solver_parsing as parsing
from tests.utils.assertions import expect

_EXPECTED_PARSING_MAX_CONSTRAINT_AST_DEPTH_256 = 256


def test_constraint_solver_parsing_contract() -> None:
    expect(parsing.MAX_CONSTRAINT_AST_DEPTH == _EXPECTED_PARSING_MAX_CONSTRAINT_AST_DEPTH_256)

    expect(not (parsing.parse_expression_to_z3("x + 1", {}, None) is not None))
    expect(parsing.convert_angr_to_z3([object()], None) == [])
    expect(parsing.extract_model(None, None) == {})
    expect(not (parsing.convert_single_constraint(True, None) is not None))
