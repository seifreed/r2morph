"""Compatibility facade for report summary aggregation helpers."""

from __future__ import annotations

from r2morph.reporting.summary_aggregator_evidence import EvidenceAggregator
from r2morph.reporting.summary_aggregator_summary import SummaryAggregator
from r2morph.reporting.summary_aggregator_symbolic_metrics import (
    SymbolicAggregator,
    SymbolicStats,
)

__all__ = [
    "EvidenceAggregator",
    "SummaryAggregator",
    "SymbolicAggregator",
    "SymbolicStats",
]
