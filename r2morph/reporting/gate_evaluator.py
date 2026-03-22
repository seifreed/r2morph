"""
Gate evaluation logic extracted from cli.py and engine.py.

This module handles severity ordering, gate failure detection,
and pass severity requirements checking.
"""

from dataclasses import dataclass
from typing import Any


SEVERITY_ORDER: dict[str, int] = {
    "mismatch": 0,
    "without-coverage": 1,
    "bounded-only": 2,
    "clean": 3,
    "not-requested": 4,
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
        severity_order = SEVERITY_ORDER
        requested = dict(gate_evaluation.get("requested", {}))
        results = dict(gate_evaluation.get("results", {}))
        pass_failures = list(results.get("require_pass_severity_failures", []))
        pass_failure_map: dict[str, list[str]] = {}
        failures_by_expected_severity: dict[str, int] = {}

        for failure in pass_failures:
            failure_text = str(failure)
            pass_name = failure_text.split("=", 1)[0].strip() or "unknown"
            pass_failure_map.setdefault(pass_name, []).append(failure_text)
            marker = "expected <= "
            if marker in failure_text:
                severity = failure_text.split(marker, 1)[1].rstrip(") ").strip()
                failures_by_expected_severity[severity] = (
                    failures_by_expected_severity.get(severity, 0) + 1
                )

        min_severity_failed = requested.get("min_severity") is not None and not results.get(
            "min_severity_passed", True
        )
        require_pass_failed = bool(pass_failures)

        return {
            "all_passed": bool(results.get("all_passed", True)),
            "min_severity_failed": min_severity_failed,
            "min_severity": requested.get("min_severity"),
            "require_pass_severity_failed": require_pass_failed,
            "require_pass_severity_failure_count": len(pass_failures),
            "require_pass_severity_failures": pass_failures,
            "require_pass_severity_failures_by_pass": pass_failure_map,
            "require_pass_severity_failures_by_expected_severity": dict(
                sorted(
                    failures_by_expected_severity.items(),
                    key=lambda item: (severity_order.get(item[0], 99), item[0]),
                )
            ),
        }

    @staticmethod
    def build_gate_failure_priority(
        gate_failures: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Build an ordered machine-readable priority list for pass gate failures."""
        if not gate_failures:
            return []

        def _expected_severity_rank(failure: str) -> int:
            marker = "expected <= "
            if marker not in failure:
                return 99
            severity = failure.split(marker, 1)[1].rstrip(") ").strip()
            severity_order = SEVERITY_ORDER
            return severity_order.get(severity, 99)

        ordered_failures = sorted(
            gate_failures.get("require_pass_severity_failures_by_pass", {}).items(),
            key=lambda item: (
                min(_expected_severity_rank(failure) for failure in item[1]),
                -len(item[1]),
                item[0],
            ),
        )

        priority = []
        for pass_name, failures in ordered_failures:
            strictest = "unknown"
            if failures:
                strictest = min(
                    (
                        failure.split("expected <= ", 1)[1].rstrip(") ").strip()
                        for failure in failures
                        if "expected <= " in failure
                    ),
                    key=lambda severity: {
                        "mismatch": 0,
                        "without-coverage": 1,
                        "bounded-only": 2,
                        "clean": 3,
                        "not-requested": 4,
                    }.get(severity, 99),
                    default="unknown",
                )
            priority.append(
                {
                    "pass_name": pass_name,
                    "failure_count": len(failures),
                    "strictest_expected_severity": strictest,
                    "failures": list(failures),
                }
            )

        return priority

    @staticmethod
    def build_gate_failure_severity_priority(
        gate_failures: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Build an ordered severity-first summary for gate failures."""
        if not gate_failures:
            return []

        severity_order = SEVERITY_ORDER

        rows = [
            {
                "severity": severity,
                "failure_count": count,
            }
            for severity, count in gate_failures.get(
                "require_pass_severity_failures_by_expected_severity", {}
            ).items()
        ]

        rows.sort(
            key=lambda item: (
                severity_order.get(item["severity"], 99),
                -item["failure_count"],
                item["severity"],
            )
        )

        return rows

    @staticmethod
    def attach_gate_evaluation(
        report_payload: dict[str, object],
        min_severity: str | None,
        min_severity_passed: bool,
        require_pass_severity: list[tuple[str, str, int]],
        require_pass_severity_passed: bool,
        require_pass_severity_failures: list[str],
    ) -> dict[str, object]:
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
        gate_failure_severity_priority = GateEvaluator.build_gate_failure_severity_priority(
            gate_failures
        )

        report_payload["gate_evaluation"] = gate_evaluation
        report_payload["gate_failures"] = gate_failures
        report_payload["gate_failure_priority"] = gate_failure_priority
        report_payload["gate_failure_severity_priority"] = gate_failure_severity_priority

        summary = dict(report_payload.get("summary", {}))
        summary["gate_evaluation"] = gate_evaluation["results"]
        summary["gate_failures"] = gate_failures
        summary["gate_failure_priority"] = gate_failure_priority
        summary["gate_failure_severity_priority"] = gate_failure_severity_priority
        report_payload["summary"] = summary

        return report_payload


def summarize_gate_failures(gate_evaluation: dict[str, Any]) -> dict[str, Any]:
    """Build a compact summary of persisted gate failures for reports."""
    severity_order = SEVERITY_ORDER
    requested = dict(gate_evaluation.get("requested", {}))
    results = dict(gate_evaluation.get("results", {}))
    pass_failures = list(results.get("require_pass_severity_failures", []))
    pass_failure_map: dict[str, list[str]] = {}
    failures_by_expected_severity: dict[str, int] = {}
    for failure in pass_failures:
        failure_text = str(failure)
        pass_name = failure_text.split("=", 1)[0].strip() or "unknown"
        pass_failure_map.setdefault(pass_name, []).append(failure_text)
        marker = "expected <= "
        if marker in failure_text:
            severity = failure_text.split(marker, 1)[1].rstrip(") ").strip()
            failures_by_expected_severity[severity] = failures_by_expected_severity.get(severity, 0) + 1
    min_severity_failed = requested.get("min_severity") is not None and not results.get("min_severity_passed", True)
    require_pass_failed = bool(pass_failures)
    return {
        "all_passed": bool(results.get("all_passed", True)),
        "min_severity_failed": min_severity_failed,
        "min_severity": requested.get("min_severity"),
        "require_pass_severity_failed": require_pass_failed,
        "require_pass_severity_failure_count": len(pass_failures),
        "require_pass_severity_failures": pass_failures,
        "require_pass_severity_failures_by_pass": pass_failure_map,
        "require_pass_severity_failures_by_expected_severity": dict(
            sorted(
                failures_by_expected_severity.items(),
                key=lambda item: (severity_order.get(item[0], 99), item[0]),
            )
        ),
    }


def build_gate_failure_priority(gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Build an ordered machine-readable priority list for pass gate failures."""
    if not gate_failures:
        return []
    severity_order = SEVERITY_ORDER

    def _expected_severity_rank(failure: str) -> int:
        marker = "expected <= "
        if marker not in failure:
            return 99
        severity = failure.split(marker, 1)[1].rstrip(") ").strip()
        return severity_order.get(severity, 99)

    ordered_failures = sorted(
        gate_failures.get("require_pass_severity_failures_by_pass", {}).items(),
        key=lambda item: (
            min(_expected_severity_rank(failure) for failure in item[1]),
            -len(item[1]),
            item[0],
        ),
    )
    priority = []
    for pass_name, failures in ordered_failures:
        strictest = "unknown"
        if failures:
            strictest = min(
                (
                    failure.split("expected <= ", 1)[1].rstrip(") ").strip()
                    for failure in failures
                    if "expected <= " in failure
                ),
                key=lambda sev: severity_order.get(sev, 99),
                default="unknown",
            )
        priority.append(
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": strictest,
                "failures": list(failures),
            }
        )
    return priority


def build_gate_failure_severity_priority(
    gate_failures: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build an ordered severity-first summary for gate failures."""
    if not gate_failures:
        return []
    severity_order = SEVERITY_ORDER
    rows = [
        {
            "severity": severity,
            "failure_count": count,
        }
        for severity, count in gate_failures.get("require_pass_severity_failures_by_expected_severity", {}).items()
    ]
    rows.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 99),
            -item["failure_count"],
            item["severity"],
        )
    )
    return rows
