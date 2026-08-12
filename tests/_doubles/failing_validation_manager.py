"""Validation manager that deterministically rejects every pass."""

from typing import Any

from r2morph.validation.manager import ValidationIssue, ValidationManager, ValidationOutcome


class FailingValidationManager(ValidationManager):
    def validate_pass(self, binary: Any, pass_result: dict[str, Any]) -> ValidationOutcome:
        return ValidationOutcome(
            validator_type="structural",
            passed=False,
            scope="pass",
            issues=[ValidationIssue(validator="test", message="forced failure")],
        )
