"""Summary aggregation helpers for report generation."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.summary_aggregator_details import summarize_diff_digest, summarize_discarded_mutations
from r2morph.reporting.summary_aggregator_overview import summarize_degradation_roles, summarize_pass_timings


class SummaryAggregator:
    """Aggregates summaries across all passes for report generation."""

    @staticmethod
    def summarize_degradation_roles(
        pass_results: dict[str, Any],
    ) -> dict[str, int]:
        """Aggregate degradation role counts across pass validation contexts."""
        return summarize_degradation_roles(pass_results)

    @staticmethod
    def summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
        """Build a compact diff digest across passes."""
        return summarize_diff_digest(pass_results)

    @staticmethod
    def summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Build a compact per-pass timing summary for tooling."""
        return summarize_pass_timings(pass_results)

    @staticmethod
    def summarize_discarded_mutations(
        discarded_mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Aggregate discarded mutations by pass and reason."""
        return summarize_discarded_mutations(discarded_mutations)
