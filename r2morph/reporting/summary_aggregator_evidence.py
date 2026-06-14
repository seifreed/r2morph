"""Evidence aggregation helpers for report summaries."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.summary_aggregator_evidence_rows import (
    _build_pass_evidence_summary,
    _summarize_pass_evidence_rows,
)


class EvidenceAggregator:
    """Aggregates evidence summaries from pass results."""

    @staticmethod
    def summarize_structural_evidence(
        structural_regions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build a compact structural-evidence digest from region-level findings."""
        validators: set[str] = set()
        severities: dict[str, int] = {}
        messages: list[str] = []

        for region in structural_regions:
            validators.update(region.get("validators", []))
            for severity in region.get("severities", []):
                severities[severity] = severities.get(severity, 0) + 1
            messages.extend(str(message) for message in region.get("messages", []))

        unique_messages = sorted({message for message in messages if message})
        return {
            "region_count": len(structural_regions),
            "validators": sorted(validators),
            "severity_counts": {
                key: severities[key] for key in sorted(severities, key=lambda item: (-severities[item], item))
            },
            "sample_messages": unique_messages[:5],
        }

    @staticmethod
    def build_for_pass(
        pass_name: str,
        pass_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a compact structural/symbolic evidence summary for one pass."""
        return _build_pass_evidence_summary(pass_name, pass_result)

    @staticmethod
    def summarize_pass_evidence(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Aggregate per-pass evidence summaries for tooling."""
        return _summarize_pass_evidence_rows(pass_results)
