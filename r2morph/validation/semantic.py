"""
Semantic validation layer for mutation passes.

Provides symbolic execution-based validation to verify semantic equivalence
between original and mutated code regions.

This module provides:
- Semantic equivalence checking using angr
- Observable comparison (registers, flags, memory)
- Structured validation reports for CI integration
"""

import logging
from datetime import datetime, timezone
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.semantic_invariants import InvariantSeverity, SemanticInvariantChecker
from r2morph.validation.semantic_models import (
    MutationRegion,
    ObservableComparison,
    SemanticCheck,
    ValidationMode,
    ValidationResultStatus,
)
from r2morph.validation.semantic_report_models import SemanticValidationReport, SemanticValidationResult
from r2morph.validation.semantic_symbolic import (
    ANGR_AVAILABLE,
    run_symbolic_validation,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ValidationMode",
    "ValidationResultStatus",
    "MutationRegion",
    "SemanticCheck",
    "SemanticValidationReport",
    "SemanticValidationResult",
    "ObservableComparison",
    "SemanticValidator",
    "validate_semantic_equivalence",
]


class SemanticValidator:
    """
    Semantic validation for mutation passes.

    Provides:
    - Invariant-based validation
    - Observable comparison using symbolic execution
    - Structured CI-ready reports
    """

    def __init__(self, binary: Binary, mode: ValidationMode = ValidationMode.STANDARD) -> None:
        """
        Initialize semantic validator.

        Args:
            binary: Binary to validate
            mode: Validation mode (fast/standard/thorough)
        """
        self.binary = binary
        self.mode = mode
        self.invariant_checker = SemanticInvariantChecker(binary)
        self._angr_available = ANGR_AVAILABLE

    def validate_mutation(
        self,
        region: MutationRegion,
        check_symbolic: bool = False,
        observables: list[str] | None = None,
    ) -> SemanticValidationResult:
        """
        Validate a mutation region.

        Args:
            region: Mutation region to validate
            check_symbolic: Whether to perform symbolic comparison
            observables: List of observables to check (registers, flags)

        Returns:
            SemanticValidationResult
        """
        import time

        start_time = time.time()

        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
            symbolic_status="not_requested" if not check_symbolic else "requested",
        )

        try:
            violations = self.invariant_checker.check_mutation(
                pass_type=region.pass_name,
                start_address=region.start_address,
                end_address=region.end_address,
                original_bytes=region.original_bytes,
                mutated_bytes=region.mutated_bytes,
            )
            result.violations = violations

            for violation in violations:
                check = SemanticCheck(
                    check_name=violation.invariant_name,
                    category=violation.category,
                    passed=False,
                    message=violation.message,
                    details={
                        "expected": str(violation.expected) if violation.expected else None,
                        "actual": str(violation.actual) if violation.actual else None,
                        "address_range": violation.address_range,
                    },
                )
                result.checks.append(check)

            if any(v.severity == InvariantSeverity.CRITICAL for v in violations):
                result.status = ValidationResultStatus.FAIL
            elif any(v.severity == InvariantSeverity.ERROR for v in violations):
                result.status = ValidationResultStatus.FAIL

            if check_symbolic and self._angr_available:
                self._run_symbolic_validation(result, observables)

        except Exception as e:
            logger.error(f"Semantic validation failed for region {region.start_address:x}: {e}")
            result.status = ValidationResultStatus.ERROR
            result.error_message = str(e)

        result.execution_time_seconds = time.time() - start_time
        return result

    def _run_symbolic_validation(
        self,
        result: SemanticValidationResult,
        observables: list[str] | None = None,
    ) -> None:
        """Run symbolic execution validation using angr."""
        run_symbolic_validation(self.binary, result, observables)

    def validate_mutations(
        self,
        regions: list[MutationRegion],
        check_symbolic: bool = False,
        observables: list[str] | None = None,
    ) -> SemanticValidationReport:
        """
        Validate multiple mutation regions.

        Args:
            regions: List of mutation regions
            check_symbolic: Whether to perform symbolic validation
            observables: List of observables to check

        Returns:
            SemanticValidationReport
        """
        results = []

        for region in regions:
            check_sym = check_symbolic and self.mode != ValidationMode.FAST
            result = self.validate_mutation(region, check_sym, observables)
            results.append(result)

        return SemanticValidationReport(
            binary_path=str(self.binary.path) if self.binary.path else "memory",
            timestamp=datetime.now(timezone.utc).isoformat(),
            mode=self.mode,
            results=results,
        )


def validate_semantic_equivalence(
    binary: Binary,
    mutations: list[dict[str, Any]],
    mode: str = "standard",
    check_symbolic: bool = False,
    observables: list[str] | None = None,
) -> dict[str, Any]:
    """
    Convenience function for semantic validation.

    Args:
        binary: Binary instance
        mutations: List of mutation dictionaries
        mode: Validation mode (fast/standard/thorough)
        check_symbolic: Whether to perform symbolic validation
        observables: List of observables to check

    Returns:
        Validation report as dictionary
    """
    mode_enum = ValidationMode(mode)

    regions = []
    for m in mutations:
        region = MutationRegion(
            start_address=m["start_address"],
            end_address=m["end_address"],
            original_bytes=(
                bytes.fromhex(m["original_bytes"]) if isinstance(m["original_bytes"], str) else m["original_bytes"]
            ),
            mutated_bytes=(
                bytes.fromhex(m["mutated_bytes"]) if isinstance(m["mutated_bytes"], str) else m["mutated_bytes"]
            ),
            pass_name=m.get("pass_name", "unknown"),
            function_address=m.get("function_address"),
            original_disasm=m.get("original_disasm"),
            mutated_disasm=m.get("mutated_disasm"),
            metadata=m.get("metadata", {}),
        )
        regions.append(region)

    validator = SemanticValidator(binary, mode_enum)
    report = validator.validate_mutations(regions, check_symbolic, observables)

    return report.to_dict()
