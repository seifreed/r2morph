"""Semantic-validation report/result models."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from r2morph.validation.semantic_invariant_models import InvariantCategory, InvariantSeverity, InvariantViolation
from r2morph.validation.semantic_models import (
    MutationRegion,
    ObservableComparison,
    SemanticCheck,
    ValidationMode,
    ValidationResultStatus,
)


@dataclass
class SemanticValidationResult:
    """Result of semantic validation for a mutation region."""

    region: MutationRegion
    status: ValidationResultStatus
    checks: list[SemanticCheck] = field(default_factory=list)
    violations: list[InvariantViolation] = field(default_factory=list)
    observables: ObservableComparison | None = None
    symbolic_status: str = "not_requested"
    symbolic_details: dict[str, Any] = field(default_factory=dict)
    execution_time_seconds: float = 0.0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "region": self.region.to_dict(),
            "status": self.status.value,
            "checks": [c.to_dict() for c in self.checks],
            "violations": [v.to_dict() for v in self.violations],
            "observables": self.observables.to_dict() if self.observables else None,
            "symbolic_status": self.symbolic_status,
            "symbolic_details": self.symbolic_details,
            "execution_time_seconds": self.execution_time_seconds,
            "error_message": self.error_message,
        }


@dataclass
class SemanticValidationReport:
    """Complete semantic validation report."""

    binary_path: str
    timestamp: str
    mode: ValidationMode
    results: list[SemanticValidationResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize computed fields."""
        if not self.summary:
            self._compute_summary()

    def _compute_summary(self) -> None:
        """Compute summary statistics."""
        passed = sum(1 for r in self.results if r.status == ValidationResultStatus.PASS)
        failed = sum(1 for r in self.results if r.status == ValidationResultStatus.FAIL)
        errors = sum(1 for r in self.results if r.status == ValidationResultStatus.ERROR)
        skipped = sum(1 for r in self.results if r.status == ValidationResultStatus.SKIP)

        total_violations = sum(len(r.violations) for r in self.results)
        critical_violations = sum(
            1 for r in self.results for v in r.violations if v.severity == InvariantSeverity.CRITICAL
        )

        by_pass: dict[str, dict[str, int]] = {}
        for result in self.results:
            pass_name = result.region.pass_name
            if pass_name not in by_pass:
                by_pass[pass_name] = {"passed": 0, "failed": 0, "total": 0}
            by_pass[pass_name]["total"] += 1
            if result.status == ValidationResultStatus.PASS:
                by_pass[pass_name]["passed"] += 1
            elif result.status == ValidationResultStatus.FAIL:
                by_pass[pass_name]["failed"] += 1

        self.summary = {
            "total_mutations": len(self.results),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "total_violations": total_violations,
            "critical_violations": critical_violations,
            "pass_rate": passed / len(self.results) if self.results else 1.0,
            "by_pass_type": by_pass,
            "overall_status": "pass" if failed == 0 and errors == 0 else "fail",
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "binary_path": self.binary_path,
            "timestamp": self.timestamp,
            "mode": self.mode.value,
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def write_report(self, path: Path) -> None:
        """Write report to file."""
        path.write_text(self.to_json())

    @classmethod
    def load_report(cls, path: Path) -> SemanticValidationReport:
        """Load report from file."""
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticValidationReport:
        """Create report from dictionary."""
        results = []
        for r in data.get("results", []):
            region = MutationRegion(
                start_address=r["region"]["start_address"],
                end_address=r["region"]["end_address"],
                original_bytes=bytes.fromhex(r["region"]["original_bytes"]),
                mutated_bytes=bytes.fromhex(r["region"]["mutated_bytes"]),
                pass_name=r["region"]["pass_name"],
                function_address=r["region"].get("function_address"),
                original_disasm=r["region"].get("original_disasm"),
                mutated_disasm=r["region"].get("mutated_disasm"),
                metadata=r["region"].get("metadata", {}),
            )
            checks = [
                SemanticCheck(
                    check_name=c["check_name"],
                    category=InvariantCategory(c["category"]),
                    passed=c["passed"],
                    message=c["message"],
                    details=c.get("details", {}),
                )
                for c in r.get("checks", [])
            ]
            violations = [
                InvariantViolation(
                    invariant_name=v["invariant_name"],
                    category=InvariantCategory(v["category"]),
                    severity=InvariantSeverity(v["severity"]),
                    address_range=tuple(v["address_range"]),
                    message=v["message"],
                    expected=v.get("expected"),
                    actual=v.get("actual"),
                    repair_hint=v.get("repair_hint"),
                    metadata=v.get("metadata", {}),
                )
                for v in r.get("violations", [])
            ]

            results.append(
                SemanticValidationResult(
                    region=region,
                    status=ValidationResultStatus(r["status"]),
                    checks=checks,
                    violations=violations,
                    observables=None,
                    symbolic_status=r.get("symbolic_status", "not_requested"),
                    symbolic_details=r.get("symbolic_details", {}),
                    execution_time_seconds=r.get("execution_time_seconds", 0.0),
                    error_message=r.get("error_message"),
                )
            )

        return cls(
            binary_path=data["binary_path"],
            timestamp=data["timestamp"],
            mode=ValidationMode(data["mode"]),
            results=results,
            summary=data.get("summary", {}),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_now(
        cls,
        *,
        binary_path: str,
        mode: ValidationMode,
        results: list[SemanticValidationResult] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SemanticValidationReport:
        """Create a report with the current timestamp."""
        return cls(
            binary_path=binary_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            results=results or [],
            metadata=metadata or {},
        )
