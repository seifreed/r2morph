"""Regression contract for the independent second-pass review."""

from pathlib import Path

from scripts.independent_review import review
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_independent_review_passes_published_artifacts() -> None:
    report = review(_ROOT)

    expect(report["passed"] is True and report["human_signoff"] == "not-attested")


def test_independent_review_includes_corpus_benchmark_check() -> None:
    report = review(_ROOT)

    expect(any(check["name"] == "adversarial_corpus_evidence" for check in report["checks"]))


def test_independent_review_validates_current_analyzer_and_fuzz_artifacts() -> None:
    report = review(_ROOT)
    names = {check["name"] for check in report["checks"]}

    expect({"ida_corpus_evidence", "ghidra_corpus_evidence", "parser_rewriter_fuzz_campaign"} <= names)
