"""
Validation management for mutation passes.
"""

from __future__ import annotations

from importlib import import_module  # noqa: F401
from typing import TYPE_CHECKING, Any

from r2morph.validation.manager_models import ValidationIssue, ValidationOutcome
from r2morph.validation.manager_pass_validation import augment_pass_validation

if TYPE_CHECKING:
    from r2morph.core.binary import Binary


def _parse_address(value: int | str | None) -> int:
    """Parse an address that may be an int or hex string like '0x401010'."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)


class ValidationManager:
    """
    Coordinates structural validation for mutations and passes.
    """

    def __init__(self, mode: str = "structural", check_abi: bool = False) -> None:
        from r2morph.validation.abi_validator import AbiValidator
        from r2morph.validation.structural_validator import StructuralValidator
        from r2morph.validation.symbolic_validator import SymbolicValidator

        self.mode = mode
        self.check_abi = check_abi
        self._structural_validator = StructuralValidator()
        self._abi_validator = AbiValidator()
        self._symbolic_validator = SymbolicValidator()

    def capture_structural_baseline(self, binary: Binary, function_address: int | None) -> dict[str, Any]:
        """Capture a lightweight baseline before mutation."""
        return self._structural_validator.capture_baseline(binary, function_address, mode=self.mode)

    def validate_mutation(self, binary: Binary, mutation: dict[str, Any]) -> ValidationOutcome:
        """Validate a single mutation record."""
        if self.mode == "off":
            return ValidationOutcome(validator_type="off", passed=True, scope="mutation")
        outcome = self._structural_validator.validate_mutation(
            binary,
            mutation,
            validator_type=self.mode,
        )
        if self.mode == "symbolic":
            outcome.metadata.update(
                {
                    "symbolic_requested": True,
                    "symbolic_proven": False,
                    "symbolic_status": "structural-fallback",
                }
            )
        return outcome

    def validate_pass(self, binary: Binary, pass_result: dict[str, Any]) -> ValidationOutcome:
        """Validate all mutations produced by a pass."""
        if self.mode == "off":
            return ValidationOutcome(validator_type="off", passed=True, scope="pass")

        pass_name = pass_result.get("pass_name")
        mutations = pass_result.get("mutations", [])
        issues: list[ValidationIssue] = []

        for mutation in mutations:
            outcome = self.validate_mutation(binary, mutation)
            issues.extend(outcome.issues)
            mutation_metadata = mutation.setdefault("metadata", {})
            mutation_metadata["structural_validation"] = outcome.to_dict()
            mutation_metadata["validation_passed"] = outcome.passed

        result = ValidationOutcome(
            validator_type=self.mode,
            passed=not issues,
            scope="pass",
            issues=issues,
            metadata={
                "pass_name": pass_name,
                "mutations_checked": len(mutations),
            },
        )
        augment_pass_validation(
            binary,
            pass_result,
            result,
            self._symbolic_validator,
            self._abi_validator,
            self.mode == "symbolic",
            self.check_abi,
        )

        return result

    def validate_abi(
        self, binary: Binary, function_address: int, mutation_regions: list[tuple[int, int]] | None = None
    ) -> dict[str, Any]:
        """
        Check ABI invariants for a function.

        Args:
            binary: Binary to check
            function_address: Function address
            mutation_regions: Optional list of mutated regions

        Returns:
            Dictionary with ABI validation results
        """
        return self._abi_validator.validate(binary, function_address, mutation_regions)
