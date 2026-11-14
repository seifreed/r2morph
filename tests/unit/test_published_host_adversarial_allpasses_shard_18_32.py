"""Regression checks for the eighteenth all-pass host analyzer shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32.json"
_SUMMARY = _ROOT / "docs/protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32-summary.json"
_SOURCE_COMMIT = "eb1fa600e36dbd538e19e1b5eae9dcba43a25f67"
_EXPECTED_FIXTURE_COUNT = 6
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT
_EXPECTED_APPLIED_RUNS = 15
_EXPECTED_COMPLETED_RUNS = 902
_EXPECTED_UNAVAILABLE_RUNS = 286
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def _report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_eighteenth_host_shard_covers_every_pass_for_each_fixture() -> None:
    report = _report()
    summary = _summary()

    expect(
        report["fixture_shard"] == summary["fixture_shard"] == {"count": 32, "index": 18}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and len(report["samples"]) == _EXPECTED_FIXTURE_COUNT
        and all(len(sample["passes"]) == _EXPECTED_PASS_COUNT for sample in report["samples"])
    )


def test_eighteenth_host_shard_records_all_transformation_outcomes() -> None:
    summary = _summary()
    statuses = summary["pass_status_counts"].values()

    expect(
        summary["applied_pass_runs"] == _EXPECTED_APPLIED_RUNS
        and summary["error_pass_runs"] == summary["omitted_pass_runs"] == 0
        and sum(counts["applied"] for counts in statuses) == _EXPECTED_APPLIED_RUNS
        and sum(counts["no-op"] for counts in statuses) == _EXPECTED_ROWS - _EXPECTED_APPLIED_RUNS
        and sum(counts["error"] for counts in statuses) == 0
        and sum(counts["omitted"] for counts in statuses) == 0
    )


def test_eighteenth_host_shard_accounts_for_every_analyzer_slot() -> None:
    analyzers = _summary()["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ROWS * 9
        and analyzers["completed_tool_runs"] == _EXPECTED_COMPLETED_RUNS
        and analyzers["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_RUNS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and analyzers["completed_tool_runs_by_tool"]
        == {
            "angr": _EXPECTED_ROWS,
            "custom": _EXPECTED_ROWS,
            "ghidra": _EXPECTED_ROWS,
            "ida-pro": _EXPECTED_ROWS,
            "objdump": _EXPECTED_ROWS,
            "radare2": _EXPECTED_ROWS,
            "unicorn": 110,
        }
        and analyzers["unavailable_tool_runs_by_tool"]
        == {"binary-ninja": _EXPECTED_ROWS, "triton": _EXPECTED_ROWS, "unicorn": 22}
    )


def test_eighteenth_host_shard_binds_source_and_report_hash() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]["platform"] == "macOS arm64"
        and summary["execution_context"]["python"] == "3.12.16"
        and summary["execution_context"]["ida_pro"] == "9.5"
    )


def test_eighteenth_host_shard_documents_unavailable_analyzers_and_scope() -> None:
    summary = _summary()
    reasons = summary["analyzer_summary"]["unavailable_reasons_by_tool"]

    expect(
        reasons["binary-ninja"] == {"analyzer license is unavailable": _EXPECTED_ROWS}
        and reasons["triton"] == {"module 'triton' is unavailable": _EXPECTED_ROWS}
        and reasons["unicorn"] == {"the installed x86 emulator does not support an instruction in this fixture": 22}
        and "Generated Linux fixtures were not included" in summary["scope"]
        and "do not establish semantic equivalence or general resistance" in summary["scope"]
    )


def test_eighteenth_host_shard_is_referenced_without_closing_readiness() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and f"docs/{_REPORT.name}" in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and f"docs/{_SUMMARY.name}" in readiness["criteria"]["published_resistance_results"]["evidence"]
    )


def test_eighteenth_host_shard_does_not_publish_analyst_paths() -> None:
    content = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS) and "SkynetOS.local" not in content)
