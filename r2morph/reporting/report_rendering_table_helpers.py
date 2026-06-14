"""Pure row builders for table-oriented report rendering."""

from __future__ import annotations

from typing import Any


def build_symbolic_summary_rows(
    *,
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    without_coverage: int,
) -> list[tuple[str, str]]:
    """Build the symbolic summary rows in display order."""
    if symbolic_requested == 0:
        return []
    return [
        ("Symbolic Regions Checked", str(symbolic_requested)),
        ("Observable Match", str(observable_match)),
        ("Observable Mismatch", str(observable_mismatch)),
        ("Bounded Only", str(bounded_only)),
        ("Without Coverage", str(without_coverage)),
    ]


def build_gate_failure_rows(
    gate_failure_priority: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Build the gate failure rows in display order."""
    return [
        (
            row.get("pass_name", "unknown"),
            str(row.get("failure_count", 0)),
            row.get("strictest_expected_severity", "unknown"),
        )
        for row in gate_failure_priority
    ]


def build_degradation_role_rows(
    degradation_summary: dict[str, Any],
) -> list[tuple[str, str]]:
    """Build the degradation role rows in display order."""
    if not degradation_summary.get("degraded_validation"):
        return []
    return [
        (role, str(count))
        for role, count in degradation_summary.get("roles", {}).items()
    ]


def build_mismatch_rows(
    mismatch_rows: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Build the only-mismatches rows in display order."""
    return [
        (
            row.get("pass_name", "unknown"),
            str(row.get("mismatch_count", 0)),
            str(row.get("region_count", 0)),
        )
        for row in mismatch_rows
    ]
