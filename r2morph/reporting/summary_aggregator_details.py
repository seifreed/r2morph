"""Detailed reporting summary aggregation helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_discarded import _summarize_discarded_mutations
from r2morph.core.report_helpers_summary_metrics import _summarize_diff_digest


def summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
    """Build a compact diff digest across passes."""
    return _summarize_diff_digest(pass_results)


def summarize_discarded_mutations(discarded_mutations: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate discarded mutations by pass and reason."""
    return _summarize_discarded_mutations(discarded_mutations)
