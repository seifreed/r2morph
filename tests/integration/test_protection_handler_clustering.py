"""Regression coverage for handler similarity measurement."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.protection_handler_clustering import measure
from tests.utils.assertions import expect

_REPORT = Path(__file__).resolve().parents[2] / "docs" / "protection-handler-clustering.json"
_MATURITY_DOC = Path(__file__).resolve().parents[2] / "docs" / "protection-maturity.md"
_EXPECTED_SCHEMA_VERSION = 2
_EXPECTED_NEAREST_COMPARISONS = 510
_EXPECTED_ABOVE_THRESHOLD = 72
_EXPECTED_ABOVE_THRESHOLD_PERCENT = 14.117647058823529


def test_measure_handler_clustering_records_cross_seed_similarity() -> None:
    result = measure(20260820, 3)

    expect(
        result["schema_version"] == _EXPECTED_SCHEMA_VERSION
        and result["cross_seed_exact_normalised_matches"] == 0
        and result["cross_seed_has_exact_normalised_matches"] is False
        and result["cross_seed_nearest_similarity_comparisons"] == _EXPECTED_NEAREST_COMPARISONS
        and result["cross_seed_nearest_similarity_above_threshold"] == _EXPECTED_ABOVE_THRESHOLD
        and result["cross_seed_nearest_similarity_above_threshold_percent"] == _EXPECTED_ABOVE_THRESHOLD_PERCENT
        and not (result["cross_seed_nearest_similarity_mean"] <= 0.0)
    )


def test_handler_clustering_report_matches_current_measurement() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(report == measure(20260820, 10))


def test_handler_clustering_maturity_doc_matches_report() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    document = _MATURITY_DOC.read_text(encoding="utf-8")

    expect(
        f"normalized nearest similarity mean `{report['cross_seed_nearest_similarity_mean']:.3f}`" in document
        and (
            f"`{report['cross_seed_nearest_similarity_above_threshold']:,}` of "
            f"`{report['cross_seed_nearest_similarity_comparisons']:,}` comparisons"
        )
        in document
        and f"exact normalized matches `{report['cross_seed_exact_normalised_matches']}`" in document
    )
