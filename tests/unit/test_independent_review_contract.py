import json
from pathlib import Path
from typing import cast

from scripts.independent_review import (
    _EXPECTED_BENCHMARK_TOOLS,
    _human_review_signoff,
    _review_live_adversarial_benchmark,
    review,
)
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def _live_campaign_report() -> dict[str, object]:
    decompiler = {
        "applied_observed_pairs": 1,
        "applied_baseline_unavailable_pairs": 0,
        "observed_pairs": 1,
        "completed_pairs": 1,
        "applied_completed_pairs": 1,
        "applied_completion_percent": 100.0,
    }
    analyzer_effectiveness = {
        "NopInsertion": {tool: {"decompiler": dict(decompiler)} for tool in ("radare2", "angr", "ghidra")}
    }
    completed = {tool: 1 for tool in _EXPECTED_BENCHMARK_TOOLS if tool != "binary-ninja"}
    completed["binary-ninja"] = 0
    return {
        "sample_count": 1,
        "pass_names": ["NopInsertion"],
        "pass_summary": {"NopInsertion": {"applied": 1}},
        "summary": {
            "expected_pass_runs": 1,
            "expected_tools": sorted(_EXPECTED_BENCHMARK_TOOLS),
            "completed_tool_runs_by_tool": completed,
            "analyzer_effectiveness_by_pass": analyzer_effectiveness,
            "missing_pass_runs": 0,
            "error_pass_runs": 0,
            "missing_tool_runs": 0,
            "error_tool_runs": 0,
        },
    }


def test_independent_review_accepts_live_campaign_report(tmp_path: Path) -> None:
    path = tmp_path / "adversarial-benchmark-merged.json"
    path.write_text(json.dumps(_live_campaign_report()), encoding="utf-8")

    check = _review_live_adversarial_benchmark(path)

    expect(check["status"] == "passed")


def test_independent_review_rejects_live_campaign_without_ghidra(tmp_path: Path) -> None:
    report = _live_campaign_report()
    summary = cast(dict[str, object], report["summary"])
    completed = cast(dict[str, int], summary["completed_tool_runs_by_tool"])
    completed["ghidra"] = 0
    path = tmp_path / "adversarial-benchmark-merged.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    check = _review_live_adversarial_benchmark(path)

    expect(check["status"] == "failed")


def test_independent_review_passes_published_artifacts() -> None:
    report = review(_ROOT)
    signoff = json.loads((_ROOT / "docs" / "human-review-signoff.json").read_text(encoding="utf-8"))

    expect(
        report["passed"] is True
        and report["human_signoff"] == "attested"
        and report["human_review"] == signoff
        and report["release_decision"]["status"] == "signoff-recorded"
    )


def test_independent_review_includes_corpus_benchmark_check() -> None:
    report = review(_ROOT)

    expect(any(check["name"] == "adversarial_corpus_evidence" for check in report["checks"]))


def test_independent_review_validates_current_analyzer_and_fuzz_artifacts() -> None:
    report = review(_ROOT)
    names = {check["name"] for check in report["checks"]}

    expect(
        {
            "adversarial_continuous_evidence_gate",
            "adversarial_signoff_blockers",
            "angr_binary_ninja_availability",
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
            "release_blocker_ledger_scope",
            "triton_corpus_evidence",
            "vm_fail_closed_diagnostics_contract",
            "vm_resistance_adversarial_scope",
            "vm_semantic_gap_scope",
        }
        <= names
    )


def test_independent_review_validates_fppackedidxnb_regression_artifact() -> None:
    report = review(_ROOT)
    checks = {check["name"]: check["status"] for check in report["checks"]}

    expect(checks["fppackedidxnb_regression_evidence"] == "passed")


def test_review_packet_records_independent_human_approval() -> None:
    packet = (_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8")
    normalized_packet = " ".join(packet.split())

    expect(
        "Result: APPROVE" in normalized_packet
        and "Findings: None reported" in normalized_packet
        and "reviewer acted independently of the authoring team" in normalized_packet
        and "specialist experience in binary rewriting and virtualization" in normalized_packet
        and "Reviewed commit: `a111f923df43a66826b71ab70db8a484532fbf3b`" in normalized_packet
    )


def test_independent_review_rejects_malformed_signoff_record(tmp_path: Path) -> None:
    signoff_path = tmp_path / "docs" / "human-review-signoff.json"
    signoff_path.parent.mkdir()
    signoff_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviewer": "Reviewer",
                "review_date_utc": "2026-11-08",
                "result": "APPROVE",
                "reviewed_commit": "not-a-commit",
                "independent": True,
                "independence_confirmation": "confirmed",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    rejected = False
    try:
        _human_review_signoff(tmp_path)
    except ValueError:
        rejected = True

    expect(rejected)
