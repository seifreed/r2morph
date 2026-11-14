"""Checks cross-seed and within-seed handler collision accounting."""

from __future__ import annotations

from scripts.protection_handler_clustering import _exact_match_metrics
from tests.utils.assertions import expect

_SIGNATURES_BY_SEED = [["shared", "shared", "seed-a-only"], ["shared", "seed-b-only"]]


def test_exact_match_metrics_classifies_each_seed_scope_correctly() -> None:
    metrics = _exact_match_metrics(_SIGNATURES_BY_SEED)

    expect(
        metrics
        == {
            "cross_seed_exact_normalised_matches": 3,
            "cross_seed_exact_normalised_match_rate": 0.6,
            "cross_seed_has_exact_normalised_matches": True,
            "cross_seed_normalised_cluster_count": 1,
            "cross_seed_largest_normalised_cluster": 2,
            "within_seed_exact_normalised_matches": 2,
            "within_seed_exact_normalised_match_rate": 0.4,
            "within_seed_has_exact_normalised_matches": True,
            "within_seed_normalised_cluster_count": 1,
            "within_seed_largest_normalised_cluster": 2,
        }
    )
