"""Data models for validation regression tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from r2morph.validation.validator import ValidationResult


class RegressionTestType(Enum):
    """Types of regression tests."""

    DETECTION_ACCURACY = "detection_accuracy"
    PERFORMANCE_BASELINE = "performance_baseline"
    API_COMPATIBILITY = "api_compatibility"
    OUTPUT_CONSISTENCY = "output_consistency"
    MUTATION_VALIDATION = "mutation_validation"


@dataclass
class BaselineResult:
    """Baseline result for regression testing."""

    test_id: str
    test_type: RegressionTestType
    input_hash: str
    expected_output: dict[str, Any]
    performance_baseline: dict[str, float]
    timestamp: str
    version: str


@dataclass
class RegressionTest:
    """A single regression test."""

    name: str
    binary_path: str
    mutations: list[str]
    test_cases: list[dict[str, Any]]
    expected_mutations: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RegressionResult:
    """Result of a regression test."""

    test_name: str
    passed: bool
    mutations_applied: int
    expected_mutations: int | None
    validation_result: ValidationResult
    timestamp: str
    errors: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "mutations_applied": self.mutations_applied,
            "expected_mutations": self.expected_mutations,
            "validation_result": self.validation_result.to_dict(),
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


@dataclass
class NewRegressionResult:
    """Enhanced result of a regression test."""

    test_id: str
    baseline: BaselineResult
    actual_output: dict[str, Any]
    performance_actual: dict[str, float]
    passed: bool
    issues: list[str]
    timestamp: str
