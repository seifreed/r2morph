"""Contracts for validation manager models."""

from r2morph.validation.manager_models import ValidationIssue, ValidationOutcome


def test_validation_issue_to_dict_normalizes_address_range() -> None:
    issue = ValidationIssue(
        validator="structural",
        message="mismatch",
        address_range=(0x10, 0x20),
        evidence={"expected": "aa"},
    )

    payload = issue.to_dict()

    assert payload["address_range"] == [0x10, 0x20]
    assert payload["evidence"] == {"expected": "aa"}


def test_validation_outcome_to_dict_serializes_issues() -> None:
    issue = ValidationIssue(validator="abi", message="violation")
    outcome = ValidationOutcome(validator_type="symbolic", passed=False, scope="pass", issues=[issue])

    payload = outcome.to_dict()

    assert payload["validator_type"] == "symbolic"
    assert payload["passed"] is False
    assert payload["scope"] == "pass"
    assert payload["issues"][0]["validator"] == "abi"
