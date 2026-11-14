"""Checks retained current-main local analyzer evidence for one corpus shard."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-local-allpasses-shard-2026-11-14-fadc0e63-summary.json"
_REPORT_PATH = _ROOT / "docs/protection-adversarial-local-allpasses-shard-2026-11-14-fadc0e63.json.gz"
_SOURCE_COMMIT = "fadc0e6302ba722f5e397cdafe70f33506baea99"
_FIXTURE_HASHES = {
    "elf_switch_pie_x86_64": "2b2bebfbfe1bf50813f641eb0b26e44ca7cc430ff0c5064ecb3abdf5aab1357f",
    "elf_vm_arith_x86_64": "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00",
    "elf_vm_fpengineidxnb_x86_64": "9f6971e93e6b3fd24f2f990b7dd273722b33044e65d2d89c113c184649675b07",
    "elf_vm_movabs_x86_64": "9d67243e403eb5fc4f736bd7186f617691275fffacb0739b464ed6da068e19a3",
}
_FIXTURE_COUNT = 4
_PASS_COUNT = 22
_PASS_ROWS = 88
_EXPECTED_ANALYZER_RUNS = 792
_COMPLETED_ANALYZER_RUNS = 616
_UNAVAILABLE_ANALYZER_RUNS = 176
_APPLIED_PASSES = 10
_NO_OP_PASSES = 78
_RUNS_PER_ANALYZER = 88
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _report() -> dict[str, object]:
    with gzip.open(_REPORT_PATH, "rt", encoding="utf-8") as report_file:
        return json.load(report_file)


def test_local_allpasses_summary_binds_report_commit_and_fixture_hashes() -> None:
    summary = _summary()
    fixtures = {fixture["name"]: fixture["sha256"] for fixture in summary["fixtures"]}

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["provenance"] == "local-source-tree"
        and summary["report_sha256"] == hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()
        and summary["uncompressed_sha256"] == hashlib.sha256(gzip.decompress(_REPORT_PATH.read_bytes())).hexdigest()
        and fixtures == _FIXTURE_HASHES
    )


def test_local_allpasses_shard_covers_each_fixture_and_pass_without_errors() -> None:
    summary = _summary()
    report = _report()

    expect(
        summary["fixture_count"] == _FIXTURE_COUNT
        and summary["pass_count_per_fixture"] == _PASS_COUNT
        and summary["pass_rows"] == _PASS_ROWS
        and len(report["samples"]) == _FIXTURE_COUNT
        and len(report["pass_names"]) == _PASS_COUNT
        and summary["pass_status_totals"]["applied"] == _APPLIED_PASSES
        and summary["pass_status_totals"]["no_op"] == _NO_OP_PASSES
        and summary["pass_status_totals"]["errors"] == 0
        and all(row["samples"] == _FIXTURE_COUNT for row in summary["passes"].values())
    )


def test_local_allpasses_shard_records_analyzer_coverage_and_unavailable_slots() -> None:
    coverage = _summary()["analyzer_coverage"]

    expect(
        coverage["expected_runs"] == _EXPECTED_ANALYZER_RUNS
        and coverage["completed_runs"] == _COMPLETED_ANALYZER_RUNS
        and coverage["unavailable_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and coverage["error_runs"] == 0
        and coverage["by_tool"]["ida-pro"]["completed"] == _RUNS_PER_ANALYZER
        and coverage["by_tool"]["ghidra"]["completed"] == _RUNS_PER_ANALYZER
        and coverage["by_tool"]["binary-ninja"]["unavailable"] == _RUNS_PER_ANALYZER
        and coverage["by_tool"]["triton"]["unavailable"] == _RUNS_PER_ANALYZER
    )


def test_local_allpasses_shard_keeps_general_release_criteria_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["release_criteria"]["all_named_adversarial_analyzers"] == "open"
        and summary["release_criteria"]["published_resistance_results"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_local_allpasses_artifacts_do_not_publish_host_paths() -> None:
    with gzip.open(_REPORT_PATH, "rt", encoding="utf-8") as report_file:
        report_text = report_file.read()
    report_text += _SUMMARY_PATH.read_text(encoding="utf-8")

    expect(not any(prefix in report_text for prefix in _HOST_PATH_PREFIXES))
