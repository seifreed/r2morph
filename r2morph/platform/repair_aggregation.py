"""Shared aggregation for per-format full-repair results."""

from __future__ import annotations

from typing import Any


def aggregate_repair_results(checks: list[tuple[str, Any]]) -> tuple[bool, list[str]]:
    """Accumulate per-check repair results, flagging a warning per failed check.

    Each check value is either a ``(success, repairs)`` tuple or a bare success
    bool (treated as no repairs). Returns the overall success flag and the
    combined repair log.
    """
    all_repairs: list[str] = []
    all_success = True
    for name, result in checks:
        if isinstance(result, tuple):
            success, repairs = result
        else:
            success, repairs = result, []
        if repairs:
            all_repairs.extend(repairs)
        if not success:
            all_success = False
            all_repairs.append(f"Warning: {name} repair may have issues")
    return all_success, all_repairs
