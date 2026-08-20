"""Regression coverage for handler similarity measurement."""

from __future__ import annotations

from scripts.protection_handler_clustering import measure
from tests.utils.assertions import expect


def test_measure_handler_clustering_records_cross_seed_similarity() -> None:
    result = measure(20260820, 3)

    expect(not (result["cross_seed_nearest_similarity_mean"] <= 0.0))
