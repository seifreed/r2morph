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
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


def test_semantic_models_round_trip() -> None:
    region = MutationRegion(
        start_address=0x1000,
        end_address=0x1004,
        original_bytes=b"\x90",
        mutated_bytes=b"\x90",
        **{MUTATION_NAME_KEY: "TestPass"},
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
        binary_path="test-data/bin",
        timestamp="2024-01-01T00:00:00+00:00",
        mode=ValidationMode.STANDARD,
        results=[result],
    )
    round_tripped = SemanticValidationReport.from_dict(report.to_dict())

    expect(report.summary["total_mutations"] == 1)
    expect(report.to_dict()["results"][0]["region"][MUTATION_NAME_KEY] == "TestPass")
    expect(round_tripped.summary["total_mutations"] == 1)
