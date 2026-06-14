from r2morph.cli_workflow_validation import resolve_min_severity, resolve_pass_severity_requirements


def test_cli_workflow_validation_contract() -> None:
    assert resolve_min_severity("high") == ("high", 3)
    resolved = resolve_pass_severity_requirements(["nop=clean"], alias_map={"nop": "nop"})
    assert resolved == [("nop", "clean", 3)]
