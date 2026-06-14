from r2morph.validation.semantic_invariant_models import (
    InvariantCategory,
    InvariantSeverity,
    InvariantViolation,
)
from r2morph.validation.semantic_models import (
    MutationRegion,
    ObservableComparison,
    SemanticCheck,
    ValidationMode,
    ValidationResultStatus,
)
from r2morph.validation.semantic_report_models import SemanticValidationReport, SemanticValidationResult


def test_semantic_models_round_trip() -> None:
    region = MutationRegion(
        start_address=0x1000,
        end_address=0x1004,
        original_bytes=b"\x90",
        mutated_bytes=b"\x90",
        pass_name="TestPass",
    )
    check = SemanticCheck(
        check_name="cf",
        category=InvariantCategory.CONTROL_FLOW,
        passed=True,
        message="ok",
    )
    violation = InvariantViolation(
        invariant_name="cf",
        category=InvariantCategory.CONTROL_FLOW,
        severity=InvariantSeverity.WARNING,
        address_range=(0x1000, 0x1004),
        message="warn",
    )
    result = SemanticValidationResult(
        region=region,
        status=ValidationResultStatus.PASS,
        checks=[check],
        violations=[violation],
        observables=ObservableComparison(),
    )
    report = SemanticValidationReport(
        binary_path="/tmp/bin",
        timestamp="2024-01-01T00:00:00+00:00",
        mode=ValidationMode.STANDARD,
        results=[result],
    )
    round_tripped = SemanticValidationReport.from_dict(report.to_dict())

    assert report.summary["total_mutations"] == 1
    assert report.to_dict()["results"][0]["region"]["pass_name"] == "TestPass"
    assert round_tripped.summary["total_mutations"] == 1
