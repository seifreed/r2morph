"""ABI-validation collaborator extracted from ValidationManager.

Owns the lazily-constructed ABIChecker and the ABI invariant / violation
checks. Imported lazily by ValidationManager.__init__ (composition
root) so the ValidationIssue dependency on r2morph.validation.manager is
not a circular import.
"""

from __future__ import annotations

from typing import Any

from r2morph.analysis.abi_checker import ABIChecker
from r2morph.core.binary import Binary
from r2morph.validation.manager import ValidationIssue


class AbiValidator:
    """ABI invariant checks for a function / pass (owns the ABIChecker)."""

    def __init__(self) -> None:
        self._abi_checker: ABIChecker | None = None

    def validate(
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
        if self._abi_checker is None:
            self._abi_checker = ABIChecker(binary)

        violations = self._abi_checker.check_all(function_address, mutation_regions)

        return {
            "passed": len(violations) == 0,
            "violations": [
                {
                    "type": v.violation_type.value,
                    "description": v.description,
                    "location": v.location,
                    "details": v.details,
                }
                for v in violations
            ],
            "violation_count": len(violations),
        }

    def collect_violations(self, binary: Binary, pass_result: dict[str, Any]) -> list[ValidationIssue]:
        """Check for ABI violations in a pass."""
        issues: list[ValidationIssue] = []

        if self._abi_checker is None:
            self._abi_checker = ABIChecker(binary)

        mutations = pass_result.get("mutations", [])
        mutation_regions: list[tuple[int, int]] = []

        for mutation in mutations:
            start = mutation.get("start_address")
            end = mutation.get("end_address")
            if start is not None and end is not None:
                mutation_regions.append((start, end))

        functions = binary.get_functions() if hasattr(binary, "get_functions") else []
        for func in functions[:5]:
            func_addr = func.get("offset") or func.get("addr", 0)
            violations = self._abi_checker.check_all(func_addr, mutation_regions if mutation_regions else None)

            for v in violations:
                issues.append(
                    ValidationIssue(
                        validator="abi",
                        message=v.description,
                        address_range=(v.location, v.location + 8),
                        severity="warning",
                        evidence=v.details,
                    )
                )

        return issues
