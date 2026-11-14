"""Checks the published evidence from three local all-pass analyzer shards."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-local-allpasses-shards-2026-11-14-654dc023-summary.json"
_SHARD_REPORTS = {
    0: _ROOT / "docs/protection-adversarial-local-allpasses-shard-2026-11-14-fadc0e63.json.gz",
    1: _ROOT / "docs/protection-adversarial-local-allpasses-shard-2026-11-14-2237bacc.json.gz",
    2: _ROOT / "docs/protection-adversarial-local-allpasses-shard-2026-11-14-654dc023.json.gz",
}
_SOURCE_COMMITS = {
    "fadc0e6302ba722f5e397cdafe70f33506baea99",
    "2237bacc13ca9818fc51fcce3d321287c0ea2570",
    "654dc023458e29bc85e3de2e32314a53746d8f49",
}
_FIXTURE_HASHES = {
    "elf_switch_pie_x86_64": "2b2bebfbfe1bf50813f641eb0b26e44ca7cc430ff0c5064ecb3abdf5aab1357f",
    "elf_vm_arith_x86_64": "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00",
    "elf_vm_fpenginearithrip_x86_64": "ba7b568f657961dbd363cf617fa3bde1a86d71a61390999115a0b40da0a5bd13",
    "elf_vm_fpengineidxnb_x86_64": "9f6971e93e6b3fd24f2f990b7dd273722b33044e65d2d89c113c184649675b07",
    "elf_vm_lea32_x86_64": "d47f12615bc30b1c123e92c6d18afefbcc14470b967349db234dd1ef62653487",
    "elf_vm_leaidx_x86_64": "d7b414685432996db3ae49b5ac10bc951d79effce167eec3c8667b70f12ebd78",
    "elf_vm_leaidxnb_x86_64": "f15c47e5bf80f4e179c1d097e364e01fab1de94786b25de765662919f9a5c9db",
    "elf_vm_movabs_x86_64": "9d67243e403eb5fc4f736bd7186f617691275fffacb0739b464ed6da068e19a3",
    "elf_vm_pie_x86_64": "19515c65476a8197da172be230e0e1ccc670828973908f1c2b2a192c1e13862f",
    "elf_vm_prologue_x86_64": "098ce19848d036aed38b6ffb32f6c4b9ac3ce717ceda955322975f8c1bf4ca9b",
    "elf_vm_run_movxfallback_x86_64": "e988ca4cccc0b33764ecc331fe84b5a5758101186db0028323f20a28a50c2e97",
    "elf_vm_shift_x86_64": "e69081768bdeabbbd59cd7611c6780857b20601969c0aa9d66ec50aefcf1cc29",
}
_FIXTURE_COUNT = 12
_PASS_COUNT = 22
_PASS_ROWS = 264
_EXPECTED_ANALYZER_RUNS = 2_376
_COMPLETED_ANALYZER_RUNS = 1_848
_UNAVAILABLE_ANALYZER_RUNS = 528
_APPLIED_PASSES = 24
_NO_OP_PASSES = 240
_RUNS_PER_ANALYZER = 264
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_three_shard_manifest_binds_reports_sources_and_fixture_hashes() -> None:
    summary = _summary()
    shards = summary["shards"]
    observed_fixtures = {fixture["name"]: fixture["sha256"] for fixture in summary["fixtures"]}

    expect(
        {shard["fixture_shard"]["index"] for shard in shards} == set(_SHARD_REPORTS)
        and {shard["source_commit"] for shard in shards} == _SOURCE_COMMITS
        and all(
            shard["report_sha256"]
            == hashlib.sha256(_SHARD_REPORTS[shard["fixture_shard"]["index"]].read_bytes()).hexdigest()
            and shard["uncompressed_sha256"]
            == hashlib.sha256(gzip.decompress(_SHARD_REPORTS[shard["fixture_shard"]["index"]].read_bytes())).hexdigest()
            for shard in shards
        )
        and observed_fixtures == _FIXTURE_HASHES
    )


def test_three_shard_manifest_covers_twelve_fixtures_and_all_pass_rows() -> None:
    summary = _summary()
    passes = summary["passes"]

    expect(
        summary["fixture_count"] == _FIXTURE_COUNT
        and summary["pass_count_per_fixture"] == _PASS_COUNT
        and summary["pass_rows"] == _PASS_ROWS
        and summary["pass_status_totals"]["applied"] == _APPLIED_PASSES
        and summary["pass_status_totals"]["no_op"] == _NO_OP_PASSES
        and summary["pass_status_totals"]["errors"] == 0
        and all(row["samples"] == _FIXTURE_COUNT for row in passes.values())
    )


def test_three_shard_manifest_records_completed_and_unavailable_analyzers() -> None:
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


def test_three_shard_manifest_keeps_release_criteria_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["release_criteria"]["all_named_adversarial_analyzers"] == "open"
        and summary["release_criteria"]["published_resistance_results"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_three_shard_reports_do_not_publish_host_paths() -> None:
    text = _SUMMARY_PATH.read_text(encoding="utf-8")
    for report_path in _SHARD_REPORTS.values():
        text += gzip.decompress(report_path.read_bytes()).decode("utf-8")

    expect(not any(prefix in text for prefix in _HOST_PATH_PREFIXES))
