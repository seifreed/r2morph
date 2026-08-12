"""Structural-validation collaborator extracted from ValidationManager.

Patch-integrity, invariant-preservation and control-flow-recovery
checks for a single mutation, plus the pre-mutation invariant baseline.
Stateless: callers pass the validation mode per call. Imported lazily
by ValidationManager.__init__ (composition root) so the
ValidationIssue/ValidationOutcome dependency on r2morph.validation.manager
is not a circular import.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from r2morph.analysis.invariants import InvariantDetector
from r2morph.core.binary import Binary
from r2morph.validation.manager_models import ValidationIssue, ValidationOutcome

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StructuralCheck:
    """Mutation location and issue sink shared by structural checks."""

    binary: Binary
    function_address: int
    start: int
    end: int
    issues: list[ValidationIssue]


class StructuralValidator:
    """Structural checks for a single mutation (no stored state)."""

    def validate_mutation(
        self,
        binary: Binary,
        mutation: dict[str, Any],
        *,
        validator_type: str,
    ) -> ValidationOutcome:
        """Validate a single mutation using structural checks."""
        issues: list[ValidationIssue] = []
        start = mutation["start_address"]
        end = mutation["end_address"]
        expected_bytes = bytes.fromhex(mutation["mutated_bytes"])
        readback = binary.read_bytes(start, len(expected_bytes))

        if readback != expected_bytes:
            issues.append(
                ValidationIssue(
                    validator="patch_integrity",
                    message="Mutated bytes do not match readback from binary",
                    address_range=(start, end),
                    evidence={
                        "expected": mutation["mutated_bytes"],
                        "actual": readback.hex(),
                    },
                )
            )

        raw_function_address = mutation.get("function_address")
        baseline = mutation.get("metadata", {}).get("structural_baseline", {})
        if raw_function_address is not None and raw_function_address != 0:
            check = StructuralCheck(binary, int(raw_function_address), start, end, issues)
            self._check_invariants(check, baseline)
            self._check_control_flow(check)

        return ValidationOutcome(
            validator_type=validator_type,
            passed=not issues,
            scope="mutation",
            issues=issues,
            metadata={"pass_name": mutation.get("pass_name")},
        )

    def _check_invariants(
        self,
        check: StructuralCheck,
        baseline: dict[str, Any],
    ) -> None:
        detector = InvariantDetector(check.binary)
        expected = baseline.get("invariants", [])
        try:
            current = detector.detect_all_invariants(check.function_address)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            check.issues.append(
                ValidationIssue(
                    validator="structural",
                    message="Failed to analyze mutated function",
                    address_range=(check.start, check.end),
                    evidence={"error": str(e), "function_address": check.function_address},
                )
            )
            current = []

        if expected:
            current_keys = {(inv.invariant_type.value, inv.location) for inv in current}
            missing = [inv for inv in expected if (inv["type"], inv["location"]) not in current_keys]
            if missing:
                check.issues.append(
                    ValidationIssue(
                        validator="invariants",
                        message="Mutation invalidated previously observed invariants",
                        address_range=(check.start, check.end),
                        evidence={"missing_invariants": missing},
                    )
                )

    def _check_control_flow(
        self,
        check: StructuralCheck,
    ) -> None:
        try:
            check.binary.get_function_disasm(check.function_address)
            check.binary.get_basic_blocks(check.function_address)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            check.issues.append(
                ValidationIssue(
                    validator="control_flow",
                    message="Failed to recover function control-flow after mutation",
                    address_range=(check.start, check.end),
                    evidence={"error": str(e), "function_address": check.function_address},
                )
            )

    def capture_baseline(
        self,
        binary: Binary,
        function_address: int | None,
        *,
        mode: str,
    ) -> dict[str, Any]:
        """Capture a lightweight invariant baseline before mutation."""
        if mode == "off" or function_address is None or function_address == 0:
            return {}

        detector = InvariantDetector(binary)
        try:
            invariants = detector.detect_all_invariants(function_address)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to capture invariants for 0x{function_address:x}: {e}")
            invariants = []

        return {
            "function_address": function_address,
            "invariant_count": len(invariants),
            "invariants": [
                {
                    "type": inv.invariant_type.value,
                    "location": inv.location,
                    "description": inv.description,
                    "details": dict(inv.details),
                }
                for inv in invariants
            ],
        }
