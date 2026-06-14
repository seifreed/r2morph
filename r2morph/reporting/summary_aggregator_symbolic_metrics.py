"""Symbolic aggregation helpers for report summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.core.report_helpers import (
    _summarize_observable_mismatches_by_pass,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_statuses,
)


@dataclass
class SymbolicStats:
    """Aggregated symbolic validation statistics."""

    symbolic_requested: int = 0
    observable_match: int = 0
    observable_mismatch: int = 0
    bounded_only: int = 0
    without_coverage: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "symbolic_requested": self.symbolic_requested,
            "observable_match": self.observable_match,
            "observable_mismatch": self.observable_mismatch,
            "bounded_only": self.bounded_only,
            "without_coverage": self.without_coverage,
        }


class SymbolicAggregator:
    """Aggregates symbolic validation statistics from mutation records."""

    @staticmethod
    def summarize_from_mutations(
        mutations: list[dict[str, Any]],
    ) -> tuple[dict[str, int], list[dict[str, Any]], dict[str, dict[str, int]]]:
        """Build global and per-pass symbolic status summaries."""
        return _summarize_symbolic_statuses(mutations)

    @staticmethod
    def summarize_coverage_by_pass(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate symbolic coverage outcomes by pass for machine-readable reports."""
        return _summarize_symbolic_coverage_by_pass(mutations)

    @staticmethod
    def summarize_issue_passes(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate symbolic issue counts by pass for machine-readable reports."""
        return _summarize_symbolic_issue_passes(mutations)

    @staticmethod
    def summarize_observable_mismatches_by_pass(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate observable symbolic mismatches by pass for report triage."""
        return _summarize_observable_mismatches_by_pass(mutations)
