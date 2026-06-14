"""Population helper for filtered-summary symbolic fallback sections."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.filtered_summary_symbolic_fallbacks import (
    _build_filtered_summary_symbolic_fallback_sections,
)


def _apply_filtered_summary_symbolic_fallback_sections(
    *,
    filtered_summary: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
) -> None:
    """Populate fallback symbolic sections when persisted data is missing."""
    fallback_sections = _build_filtered_summary_symbolic_fallback_sections(by_pass=by_pass)
    if not filtered_summary["symbolic_issue_passes"] and by_pass:
        filtered_summary["symbolic_issue_passes"] = fallback_sections["symbolic_issue_passes"]
    if not filtered_summary["symbolic_coverage_by_pass"] and by_pass:
        filtered_summary["symbolic_coverage_by_pass"] = fallback_sections["symbolic_coverage_by_pass"]
    if by_pass and (
        not filtered_summary["symbolic_severity_by_pass"]
        or all(row.get("severity") == "not-requested" for row in filtered_summary["symbolic_severity_by_pass"])
    ):
        filtered_summary["symbolic_severity_by_pass"] = fallback_sections["symbolic_severity_by_pass"]
