"""Contracts for validation manager models."""

from r2morph.validation.manager_models import ValidationIssue, ValidationOutcome
from tests.utils.assertions import expect


def test_validation_issue_to_dict_normalizes_address_range() -> None:
    issue = ValidationIssue(
        validator="structural",
        message="mismatch",
        address_range=(0x10, 0x20),
        evidence={"expected": "aa"},
    )

    payload = issue.to_dict()

    expect(payload["address_range"] == [16, 32])
    expect(payload["evidence"] == {"expected": "aa"})


def test_validation_outcome_to_dict_serializes_issues() -> None:
    issue = ValidationIssue(validator="abi", message="violation")
    outcome = ValidationOutcome(validator_type="symbolic", passed=False, scope="pass", issues=[issue])

    payload = outcome.to_dict()

    expect(payload["validator_type"] == "symbolic")
    expect(not (payload["passed"] is not False))
    expect(payload["scope"] == "pass")
    expect(payload["issues"][0]["validator"] == "abi")
