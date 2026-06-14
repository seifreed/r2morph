"""
Gate evaluation logic extracted from cli.py and engine.py.

This module handles severity ordering, gate failure detection,
and pass severity requirements checking.
"""

from dataclasses import dataclass
from typing import Any

from r2morph.core.constants import SEVERITY_ORDER
from r2morph.reporting.gate_failure_summary import (
    build_gate_failure_priority as _build_gate_failure_priority,
)
from r2morph.reporting.gate_failure_summary import (
    build_gate_failure_severity_priority as _build_gate_failure_severity_priority,
)
from r2morph.reporting.gate_failure_summary import (
    summarize_gate_failures as _summarize_gate_failures,
)

ROLLBACK_SEVERITY_ORDER: dict[str, int] = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


@dataclass
class GateFailure:
    """Represents a gate failure for a specific pass."""

    pass_name: str
    expected_severity: str
    actual_severity: str
    failure_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass_name": self.pass_name,
            "expected_severity": self.expected_severity,
            "actual_severity": self.actual_severity,
            "failure_text": self.failure_text,
        }


class GateEvaluator:
    """Evaluates severity thresholds and gate failures for mutation reports."""

    @staticmethod
    def severity_rank(severity: str) -> int:
        """Get the numeric rank for a severity level."""
        return SEVERITY_ORDER.get(severity, 99)

    @staticmethod
    def parse_pass_severity_requirements(
        requirements: list[str] | None,
        alias_map: dict[str, str] | None = None,
    ) -> list[tuple[str, str, int]]:
        """Parse repeated PassName=severity requirements for mutate gating."""
        resolved: list[tuple[str, str, int]] = []
        aliases = {key.strip(): value for key, value in (alias_map or {}).items()}
        valid_pass_names = set(aliases.values())

        for item in requirements or []:
            if "=" not in item:
                continue
            pass_name, severity = item.split("=", 1)
            pass_name = pass_name.strip()
            severity = severity.strip()
            pass_name = aliases.get(pass_name, pass_name)

            if not pass_name or severity not in SEVERITY_ORDER:
                continue
            if valid_pass_names and pass_name not in valid_pass_names:
                continue

            resolved.append((pass_name, severity, SEVERITY_ORDER[severity]))

        return resolved

    @staticmethod
    def check_pass_severity_requirements(
        severity_rows: list[dict[str, object]],
        requirements: list[tuple[str, str, int]],
    ) -> tuple[bool, list[str]]:
        """Check whether all required passes meet their minimum allowed severity rank."""
        if not requirements:
            return True, []

        by_pass = {str(row.get("pass_name", "")): row for row in severity_rows}
        failures: list[str] = []

        for pass_name, severity, rank in requirements:
            row = by_pass.get(pass_name)
            if row is None:
                failures.append(f"{pass_name}=missing(expected <= {severity})")
                continue
            actual = str(row.get("severity", "not-requested"))
            actual_rank = SEVERITY_ORDER.get(actual, 99)
            if actual_rank > rank:
                failures.append(f"{pass_name}={actual}(expected <= {severity})")

        return not failures, failures

    @staticmethod
    def summarize_gate_failures(gate_evaluation: dict[str, Any]) -> dict[str, Any]:
        """Build a compact summary of persisted gate failures for reports."""
        return _summarize_gate_failures(gate_evaluation)

    @staticmethod
    def build_gate_failure_priority(
        gate_failures: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Build an ordered machine-readable priority list for pass gate failures."""
        return _build_gate_failure_priority(gate_failures)

    @staticmethod
    def build_gate_failure_severity_priority(
        gate_failures: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Build an ordered severity-first summary for gate failures."""
        return _build_gate_failure_severity_priority(gate_failures)

    @staticmethod
    def attach_gate_evaluation(
        report_payload: dict[str, Any],
        min_severity: str | None,
        min_severity_passed: bool,
        require_pass_severity: list[tuple[str, str, int]],
        require_pass_severity_passed: bool,
        require_pass_severity_failures: list[str],
    ) -> dict[str, Any]:
        """Attach CLI gate evaluation metadata to a report payload."""
        gate_evaluation = {
            "requested": {
                "min_severity": min_severity,
                "require_pass_severity": [
                    {"pass_name": pass_name, "max_severity": severity}
                    for pass_name, severity, _rank in require_pass_severity
                ],
            },
            "results": {
                "min_severity_passed": min_severity_passed,
                "require_pass_severity_passed": require_pass_severity_passed,
                "require_pass_severity_failures": list(require_pass_severity_failures),
                "all_passed": min_severity_passed and require_pass_severity_passed,
            },
        }
        gate_failures = GateEvaluator.summarize_gate_failures(gate_evaluation)
        gate_failure_priority = GateEvaluator.build_gate_failure_priority(gate_failures)
        gate_failure_severity_priority = GateEvaluator.build_gate_failure_severity_priority(gate_failures)

        report_payload["gate_evaluation"] = gate_evaluation
        report_payload["gate_failures"] = gate_failures
        report_payload["gate_failure_priority"] = gate_failure_priority
        report_payload["gate_failure_severity_priority"] = gate_failure_severity_priority

        summary: dict[str, Any] = dict(report_payload.get("summary", {}) or {})
        summary["gate_evaluation"] = gate_evaluation["results"]
        summary["gate_failures"] = gate_failures
        summary["gate_failure_priority"] = gate_failure_priority
        summary["gate_failure_severity_priority"] = gate_failure_severity_priority
        report_payload["summary"] = summary

        return report_payload


def summarize_gate_failures(gate_evaluation: dict[str, Any]) -> dict[str, Any]:
    """Build a compact summary of persisted gate failures for reports."""
    return _summarize_gate_failures(gate_evaluation)


def build_gate_failure_priority(gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Build an ordered machine-readable priority list for pass gate failures."""
    return _build_gate_failure_priority(gate_failures)


def build_gate_failure_severity_priority(
    gate_failures: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build an ordered severity-first summary for gate failures."""
    return _build_gate_failure_severity_priority(gate_failures)


class GateFailureReporter:
    """Service adapter over the module-level gate-failure report helpers."""

    def summarize_gate_failures(self, gate_evaluation: dict[str, Any]) -> dict[str, Any]:
        return summarize_gate_failures(gate_evaluation)

    def build_gate_failure_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        return build_gate_failure_priority(gate_failures)

    def build_gate_failure_severity_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        return build_gate_failure_severity_priority(gate_failures)
