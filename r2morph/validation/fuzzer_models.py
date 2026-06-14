"""Campaign result models for the legacy validation fuzzer."""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.validation.validator import ValidationResult


@dataclass
class FuzzResult:
    """Result of fuzzing campaign."""

    total_tests: int
    passed: int
    failed: int
    crashes: int
    timeouts: int
    validation_results: list[ValidationResult]

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        return (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"Fuzz Results:\n"
            f"  Total: {self.total_tests}\n"
            f"  Passed: {self.passed} ({self.success_rate:.1f}%)\n"
            f"  Failed: {self.failed}\n"
            f"  Crashes: {self.crashes}\n"
            f"  Timeouts: {self.timeouts}"
        )
