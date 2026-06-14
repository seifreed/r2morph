"""Detailed reporting summary aggregation helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers import _summarize_diff_digest, _summarize_discarded_mutations


def summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
    """Build a compact diff digest across passes."""
    return _summarize_diff_digest(pass_results)


def summarize_discarded_mutations(discarded_mutations: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate discarded mutations by pass and reason."""
    return _summarize_discarded_mutations(discarded_mutations)
