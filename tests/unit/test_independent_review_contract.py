"""Regression contract for the independent second-pass review."""

from pathlib import Path

from scripts.independent_review import review
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_independent_review_passes_published_artifacts() -> None:
    report = review(_ROOT)

    expect(report["passed"] is True and report["human_signoff"] == "not-attested")
