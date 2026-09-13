"""Regression contract for the independent second-pass review."""

from pathlib import Path

from scripts.independent_review import review
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_independent_review_passes_published_artifacts() -> None:
    report = review(_ROOT)

    expect(
        report["passed"] is True
        and report["human_signoff"] == "not-attested"
        and report["release_decision"]["status"] == "block-vm-milestone"
    )


def test_independent_review_includes_corpus_benchmark_check() -> None:
    report = review(_ROOT)

    expect(any(check["name"] == "adversarial_corpus_evidence" for check in report["checks"]))


def test_independent_review_validates_current_analyzer_and_fuzz_artifacts() -> None:
    report = review(_ROOT)
    names = {check["name"] for check in report["checks"]}

    expect(
        {
            "adversarial_signoff_blockers",
            "ida_corpus_evidence",
            "ida_current_summary_evidence",
            "binary_ninja_benchmark_contract",
            "differential_continuous_evidence_gate",
            "differential_corpus_gap_scope",
            "differential_platform_gap_scope",
            "ghidra_corpus_evidence",
            "official_target_scope",
            "pass_maturity_gap_scope",
            "parser_rewriter_fuzz_campaign",
            "vm_resistance_adversarial_scope",
            "vm_semantic_gap_scope",
        }
        <= names
    )


def test_independent_review_validates_fppackedidxnb_regression_artifact() -> None:
    report = review(_ROOT)
    checks = {check["name"]: check["status"] for check in report["checks"]}

    expect(checks["fppackedidxnb_regression_evidence"] == "passed")
