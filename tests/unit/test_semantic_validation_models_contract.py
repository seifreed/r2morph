from r2morph.mutations.semantic_validation_models import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)
from tests.utils.assertions import expect


def test_validation_models_round_trip():
    issue = ValidationIssue(
        code="STACK_UNBALANCED",
        severity=ValidationSeverity.ERROR,
        message="stack changed",
        address=0x1000,
        details={"depth": 1},
    )
    result = ValidationResult(valid=True, issues=[issue], metadata={"arch": "x86_64"})

    expect(result.errors == [issue])
    expect(result.warnings == [])
    result.add_warning("SAFE_OPCODE", "ok", 0x1002)
    result.add_error("BAD_OPCODE", "bad", 0x1004)

    expect(not (result.valid is not False))
    expect([item.code for item in result.errors] == ["STACK_UNBALANCED", "BAD_OPCODE"])
    expect([item.code for item in result.warnings] == ["SAFE_OPCODE"])
