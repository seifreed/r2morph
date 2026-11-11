"""Regression contracts for the pinned adversarial campaign evidence."""

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-adversarial-campaign-2026-11-11-4749bca3.json"
_EXPECTED_PASS_COUNT = 22
_EXPECTED_PASS_RUNS = 7964
_EXPECTED_ANALYZER_RUNS = 71676
_COMPLETED_ANALYZER_RUNS = 55220
_UNAVAILABLE_ANALYZER_RUNS = 16456
_EXPECTED_ADVERSARIAL_BLOCKERS = 17
_COMPLETE_COVERAGE_PERCENT = 100.0
_UNAVAILABLE_RUNS_BY_ANALYZER = {"binary-ninja": 7964, "ida-pro": 7964, "unicorn": 528}


def test_adversarial_campaign_covers_every_pass_without_missing_rows() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    campaign = report["campaign"]

    expect(
        campaign["status"] == "completed"
        and campaign["expected_pass_runs"] == campaign["observed_pass_runs"] == _EXPECTED_PASS_RUNS
        and campaign["missing_pass_runs"] == 0
        and campaign["error_pass_runs"] == 0
        and report["scope"]["pass_count"] == len(report["scope"]["pass_rows"]) == _EXPECTED_PASS_COUNT
        and campaign["required_decompiler_pass_count"] == _EXPECTED_PASS_COUNT
        and campaign["decompiler_incomplete_passes"] == []
    )


def test_adversarial_campaign_keeps_unavailable_analyzers_as_blockers() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    campaign = report["campaign"]

    expect(
        campaign["expected_analyzer_runs"] == campaign["observed_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and campaign["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUNS
        and campaign["unavailable_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and campaign["blocker_totals"]["total_adversarial_evidence_blockers"] == _EXPECTED_ADVERSARIAL_BLOCKERS
        and campaign["unavailable_runs_by_analyzer"] == _UNAVAILABLE_RUNS_BY_ANALYZER
        and campaign["completed_coverage_percent_by_analyzer"]["triton"] == _COMPLETE_COVERAGE_PERCENT
        and campaign["completed_runs_by_analyzer"]["triton"] == _EXPECTED_PASS_RUNS
    )


def test_vm_smoke_does_not_claim_general_adversarial_resistance() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    smoke = report["vm_resistance_smoke"]

    expect(
        smoke["evidence_quality"] == "automated-adversarial-smoke"
        and smoke["automated_status"] == "completed"
        and smoke["human_review_status"] == "pending-human-adversarial-review"
        and smoke["claim"] == "automated-smoke-only; general resistance is not established"
        and report["readiness"]["published_resistance_results"] == "open"
    )


def test_vm_smoke_report_hashes_match_pinned_reports() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    smoke = report["vm_resistance_smoke"]
    paths = {
        "adversarial": smoke["adversarial_report"],
        "seed_diversity": smoke["seed_diversity_report"],
        "bytecode_grammar": smoke["bytecode_grammar_report"],
    }
    hashes = {name: hashlib.sha256((_ROOT / path).read_bytes()).hexdigest() for name, path in paths.items()}

    expect(hashes == smoke["report_sha256"])
