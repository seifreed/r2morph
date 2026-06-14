"""Pure formatting helpers for pass rendering sections."""

from __future__ import annotations

from typing import Any


def build_pass_capability_fragments(pass_capabilities: dict[str, Any]) -> list[str]:
    """Build the compact capability fragments for a pass."""
    fragments = []
    runtime = pass_capabilities.get("runtime", {}) or {}
    symbolic = pass_capabilities.get("symbolic", {}) or {}
    runtime_recommended = runtime.get("recommended")
    symbolic_confidence = symbolic.get("confidence")
    symbolic_recommended = symbolic.get("recommended")
    if runtime_recommended is not None:
        fragments.append(f"runtime recommended={'yes' if runtime_recommended else 'no'}")
    if symbolic_confidence:
        fragments.append(f"symbolic confidence={symbolic_confidence}")
    if symbolic_recommended is not None:
        fragments.append(f"symbolic recommended={'yes' if symbolic_recommended else 'no'}")
    return fragments


def build_pass_validation_context_fragments(
    context: dict[str, Any],
) -> list[str]:
    """Build the compact validation-context fragments for a pass."""
    fragments = [
        f"requested={context.get('requested_validation_mode', 'unknown')}",
        f"effective={context.get('effective_validation_mode', 'unknown')}",
    ]
    if context.get("degraded_execution"):
        fragments.append("degraded=yes")
    if context.get("degradation_triggered_by_pass"):
        fragments.append("trigger=yes")
        fragments.append("role=degradation-trigger")
    elif context.get("degraded_execution"):
        fragments.append("role=executed-under-degraded-mode")
    else:
        fragments.append(f"role={context.get('role', 'requested-mode')}")
    return fragments


def build_pass_region_label(start: Any, end: Any) -> str:
    """Format a compact region label from start/end addresses."""
    if start is None or end is None:
        return "unknown"
    if start == end:
        return f"0x{start:x}"
    return f"0x{start:x}-0x{end:x}"


def group_issues_by_severity(issues_list: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Aggregate issue counters by severity for rendering."""
    issues_by_severity: dict[str, dict[str, int]] = {}
    for issue in issues_list:
        sev = issue.get("severity", "unknown")
        if sev not in issues_by_severity:
            issues_by_severity[sev] = {"mismatch": 0, "without_coverage": 0, "bounded_only": 0}
        issues_by_severity[sev]["mismatch"] += issue.get("observable_mismatch", 0)
        issues_by_severity[sev]["without_coverage"] += issue.get("without_coverage", 0)
        issues_by_severity[sev]["bounded_only"] += issue.get("bounded_only", 0)
    return issues_by_severity
