"""Regression checks for the sixteenth all-pass host analyzer shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32-summary.json"
_EXPECTED_FIXTURE_COUNT = 6
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT
_EXPECTED_APPLIED_RUNS = 12
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def test_sixteenth_host_shard_covers_all_passes_and_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == summary["fixture_shard"] == {"count": 32, "index": 16}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and len(report["samples"]) == _EXPECTED_FIXTURE_COUNT
        and all(len(sample["passes"]) == _EXPECTED_PASS_COUNT for sample in report["samples"])
    )


def test_sixteenth_host_shard_records_all_pass_outcomes() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["applied_pass_runs"] == _EXPECTED_APPLIED_RUNS
        and summary["error_pass_runs"] == 0
        and summary["omitted_pass_runs"] == 0
        and sum(counts["applied"] for counts in summary["pass_status_counts"].values()) == _EXPECTED_APPLIED_RUNS
        and sum(counts["no-op"] for counts in summary["pass_status_counts"].values())
        == _EXPECTED_ROWS - _EXPECTED_APPLIED_RUNS
        and sum(counts["error"] for counts in summary["pass_status_counts"].values()) == 0
        and sum(counts["omitted"] for counts in summary["pass_status_counts"].values()) == 0
    )


def test_sixteenth_host_shard_accounts_for_all_analyzer_runs() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    analyzers = summary["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ROWS * 9
        and analyzers["completed_tool_runs"] == _EXPECTED_ROWS * len(analyzers["completed_tool_runs_by_tool"])
        and analyzers["unavailable_tool_runs"] == _EXPECTED_ROWS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and analyzers["completed_tool_runs_by_tool"]
        == {
            name: _EXPECTED_ROWS
            for name in ("angr", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn")
        }
        and analyzers["unavailable_tool_runs_by_tool"] == {"binary-ninja": _EXPECTED_ROWS}
        and analyzers["unavailable_reasons_by_tool"]["binary-ninja"]
        == {"analyzer license is unavailable": _EXPECTED_ROWS}
    )


def test_sixteenth_host_shard_binds_source_and_report_digest() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "61f152e259a040a6316b6247218d7dc3f67af73c"
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]["platform"] == "macOS arm64"
        and summary["execution_context"]["python"] == "3.13.11"
    )


def test_sixteenth_host_shard_preserves_bounded_scope() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["scope"]
        == (
            "Six repository fixtures across one 32-shard slice only. Binary Ninja was unavailable because its license "
            "was invalid; generated Linux fixtures were not included. Analyzer metrics are bounded structural "
            "observations and do not prove semantic equivalence or general resistance."
        )
    )


def test_sixteenth_host_shard_does_not_publish_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
