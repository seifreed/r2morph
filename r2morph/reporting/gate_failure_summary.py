"""Gate failure summary and prioritization helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import SEVERITY_ORDER


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
