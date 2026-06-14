from r2morph.analysis.symbolic import constraint_solver_parsing as parsing


def test_constraint_solver_parsing_contract() -> None:
    assert parsing.MAX_CONSTRAINT_AST_DEPTH == 256

    assert parsing.parse_expression_to_z3("x + 1", {}, None) is None
    assert parsing.convert_angr_to_z3([object()], None) == []
    assert parsing.extract_model(None, None) == {}
    assert parsing.convert_single_constraint(True, None) is None
