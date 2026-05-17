"""
Validation management for mutation passes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from importlib import import_module
from typing import Any

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


@dataclass
class ValidationIssue:
    """Represents a validation failure or warning."""

    validator: str
    message: str
    address_range: tuple[int, int] | None = None
    severity: str = "error"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        payload = asdict(self)
        if self.address_range is not None:
            payload["address_range"] = [self.address_range[0], self.address_range[1]]
        return payload


@dataclass
class ValidationOutcome:
    """Result of a validation run."""

    validator_type: str
    passed: bool
    scope: str
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "validator_type": self.validator_type,
            "passed": self.passed,
            "scope": self.scope,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


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

    def _validate_structural_mutation(
        self,
        binary: Binary,
        mutation: dict[str, Any],
        *,
        validator_type: str,
    ) -> ValidationOutcome:
        """Validate a single mutation using structural checks."""
        return self._structural_validator.validate_mutation(binary, mutation, validator_type=validator_type)

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
        if self.mode == "symbolic":
            result.metadata.update(self._symbolic_validator._run_symbolic_precheck(binary, pass_result))
            bridge_module = import_module("r2morph.analysis.symbolic.angr_bridge")
            if pass_result.get("pass_name") in {
                "InstructionSubstitution",
                "NopInsertion",
                "RegisterSubstitution",
            }:
                result.metadata.update(
                    self._symbolic_validator._compare_real_binary_regions(binary, pass_result, bridge_module)
                )
                if result.metadata.get("symbolic_binary_check_performed"):
                    if result.metadata.get("symbolic_binary_equivalent"):
                        result.metadata["symbolic_status"] = "real-binary-observables-match"
                        result.metadata["symbolic_reason"] = (
                            "bounded real-binary symbolic effects matched for the mutated regions"
                        )
                    else:
                        result.metadata["symbolic_status"] = "real-binary-observable-mismatch"
                        result.metadata["symbolic_reason"] = (
                            "bounded real-binary symbolic effects diverged for the mutated regions"
                        )
            self._symbolic_validator._annotate_mutations_with_symbolic_metadata(pass_result, result.metadata)

        if self.check_abi:
            abi_issues = self._check_abi_violations(binary, pass_result)
            issues.extend(abi_issues)
            if abi_issues:
                result.issues.extend(abi_issues)
                result.passed = False
                result.metadata["abi_violations"] = len(abi_issues)

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

    def _check_abi_violations(self, binary: Binary, pass_result: dict[str, Any]) -> list[ValidationIssue]:
        """Check for ABI violations in a pass."""
        return self._abi_validator.collect_violations(binary, pass_result)
