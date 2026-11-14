"""Regression checks for the two-fixture local analyzer campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-adversarial-local-multianalyzer-two-fixture-2026-11-14-f1fec959.json"
_SUMMARY = _ROOT / "docs" / "protection-adversarial-local-multianalyzer-two-fixture-2026-11-14-f1fec959-summary.json"
_FIXTURES = {
    "elf_vm_arith_x86_64": "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00",
    "elf_x86_64": "7b2dd51db978d08f362c2b7a0b6062521340207faf1955407361ae3a3268f50a",
}
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_FIXTURE_COUNT = 2
_PASS_COUNT = 22
_APPLIED_PASSES_PER_FIXTURE = 2
_NO_OP_PASSES_PER_FIXTURE = 20
_RUNS_PER_TOOL = 44
_EXPECTED_ANALYZER_RUNS = 396
_COMPLETED_ANALYZER_RUNS = 352
_UNAVAILABLE_ANALYZER_RUNS = 44


def test_two_fixture_summary_binds_source_report_and_fixture_hashes() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "f1fec9591cc7759ca5303a02f97d43d083ea9ea6"
        and summary["provenance"] == "local-source-tree"
        and summary["report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and {fixture["name"]: fixture["sha256"] for fixture in summary["fixtures"]} == _FIXTURES
    )


def test_two_fixture_campaign_records_each_pass_status() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    passes = summary["passes"]

    expect(
        summary["fixture_count"] == _FIXTURE_COUNT
        and summary["pass_count_per_fixture"] == _PASS_COUNT
        and summary["pass_rows"] == _FIXTURE_COUNT * _PASS_COUNT
        and summary["pass_status_totals"]
        == {
            "applied": _FIXTURE_COUNT * _APPLIED_PASSES_PER_FIXTURE,
            "no_op": _FIXTURE_COUNT * _NO_OP_PASSES_PER_FIXTURE,
            "errors": 0,
            "omitted": 0,
        }
        and passes["CodeVirtualization"]["applied"] == _FIXTURE_COUNT
        and passes["InstructionSubstitution"]["applied"] == _FIXTURE_COUNT
        and all(
            row["no_op"] == _FIXTURE_COUNT
            for name, row in passes.items()
            if name not in ("CodeVirtualization", "InstructionSubstitution")
        )
    )


def test_two_fixture_campaign_records_analyzer_slot_coverage() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    coverage = summary["analyzer_coverage"]

    expect(
        coverage["expected_runs"] == _EXPECTED_ANALYZER_RUNS
        and coverage["completed_runs"] == _COMPLETED_ANALYZER_RUNS
        and coverage["unavailable_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and coverage["error_runs"] == 0
        and coverage["by_tool"]["ida-pro"]["completed"] == _RUNS_PER_TOOL
        and coverage["by_tool"]["ghidra"]["completed"] == _RUNS_PER_TOOL
        and coverage["by_tool"]["triton"]["completed"] == _RUNS_PER_TOOL
        and coverage["by_tool"]["binary-ninja"]["unavailable"] == _RUNS_PER_TOOL
    )


def test_two_fixture_campaign_keeps_general_release_criteria_open() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads((_ROOT / "docs" / "one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["release_criteria"]["all_named_adversarial_analyzers"] == "open"
        and summary["release_criteria"]["published_resistance_results"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_two_fixture_campaign_does_not_publish_host_paths() -> None:
    report_text = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(prefix in report_text for prefix in _HOST_PATH_PREFIXES))
