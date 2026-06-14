"""Overview summary aggregation helpers for report generation."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers import _summarize_degradation_roles, _summarize_pass_timings


def summarize_degradation_roles(pass_results: dict[str, Any]) -> dict[str, int]:
    """Aggregate degradation role counts across pass validation contexts."""
    return _summarize_degradation_roles(pass_results)


def summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a compact per-pass timing summary for tooling."""
    return _summarize_pass_timings(pass_results)
