from r2morph.mutations.semantic_validation_models import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)


def test_validation_models_round_trip():
    issue = ValidationIssue(
        code="STACK_UNBALANCED",
        severity=ValidationSeverity.ERROR,
        message="stack changed",
        address=0x1000,
        details={"depth": 1},
    )
    result = ValidationResult(valid=True, issues=[issue], metadata={"arch": "x86_64"})

    assert result.errors == [issue]
    assert result.warnings == []
    result.add_warning("SAFE_OPCODE", "ok", 0x1002)
    result.add_error("BAD_OPCODE", "bad", 0x1004)

    assert result.valid is False
    assert [item.code for item in result.errors] == ["STACK_UNBALANCED", "BAD_OPCODE"]
    assert [item.code for item in result.warnings] == ["SAFE_OPCODE"]
