from r2morph.cli_workflow_validation import resolve_min_severity, resolve_pass_severity_requirements
from tests.utils.assertions import expect


def test_cli_workflow_validation_contract() -> None:
    expect(resolve_min_severity("mismatch") == ("mismatch", 0))
    resolved = resolve_pass_severity_requirements(["nop=clean"], alias_map={"nop": "nop"})
    expect(resolved == [("nop", "clean", 3)])
