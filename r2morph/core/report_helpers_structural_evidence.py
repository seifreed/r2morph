"""Structural evidence summary helpers for report generation."""

from __future__ import annotations

from typing import Any


def _summarize_structural_evidence(
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
