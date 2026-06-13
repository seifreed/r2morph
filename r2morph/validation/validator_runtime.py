"""Runtime validation data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuntimeComparisonConfig:
    """Controls what runtime signals are compared."""

    compare_exitcode: bool = True
    compare_stdout: bool = True
    compare_stderr: bool = True
    compare_files: bool = False
    normalize_whitespace: bool = False
    monitored_files: list[str] = field(default_factory=list)


@dataclass
class ValidationTestCase:
    """Runtime test case for original vs mutated binaries."""

    args: list[str] = field(default_factory=list)
    stdin: str = ""
    env: dict[str, str] = field(default_factory=dict)
    expected_exitcode: int = 0
    description: str = ""
    working_dir: str | None = None
    monitored_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "args": list(self.args),
            "stdin": self.stdin,
            "env": dict(self.env),
            "expected_exitcode": self.expected_exitcode,
            "description": self.description,
            "working_dir": self.working_dir,
            "monitored_files": list(self.monitored_files),
        }


@dataclass
class ValidationResult:
    """Result of binary validation."""

    passed: bool
    original_output: str
    mutated_output: str
    original_exitcode: int
    mutated_exitcode: int
    errors: list[str]
    similarity_score: float
    compared_signals: dict[str, bool] = field(default_factory=dict)
    file_differences: dict[str, dict[str, str]] = field(default_factory=dict)
    output_hashes: dict[str, str] = field(default_factory=dict)
    runtime_details: list[dict[str, Any]] = field(default_factory=list)
    test_cases: list[dict[str, Any]] = field(default_factory=list)

    def __str__(self) -> str:
        status = "✅ PASSED" if self.passed else "❌ FAILED"
        return (
            f"{status}\n"
            f"Exit codes: {self.original_exitcode} vs {self.mutated_exitcode}\n"
            f"Output similarity: {self.similarity_score:.1f}%\n"
            f"Errors: {len(self.errors)}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the validation result to a dict."""
        return {
            "passed": self.passed,
            "original_output": self.original_output,
            "mutated_output": self.mutated_output,
            "original_exitcode": self.original_exitcode,
            "mutated_exitcode": self.mutated_exitcode,
            "errors": list(self.errors),
            "similarity_score": self.similarity_score,
            "compared_signals": dict(self.compared_signals),
            "file_differences": dict(self.file_differences),
            "output_hashes": dict(self.output_hashes),
            "runtime_details": list(self.runtime_details),
            "test_cases": list(self.test_cases),
        }
