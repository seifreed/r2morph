"""Per-pass evidence row builders for report summaries."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers import _build_evidence_summary_for_pass, _summarize_pass_evidence


def _build_pass_evidence_summary(
    pass_name: str,
    pass_result: dict[str, Any],
) -> dict[str, Any]:
    """Build a compact structural/symbolic evidence summary for one pass."""
    return _build_evidence_summary_for_pass(pass_name, pass_result)


def _summarize_pass_evidence_rows(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Aggregate per-pass evidence summaries for tooling."""
    return _summarize_pass_evidence(pass_results)
