"""Regression checks for the 32-shard fourteenth host analyzer report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-acfc0995-shard-14-32.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-acfc0995-shard-14-32-summary.json"
_EXPECTED_FIXTURE_COUNT = 5
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT
_EXPECTED_APPLIED_RUNS = 12
_EXPECTED_TOOLS = {
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
}
_EXPECTED_COMPLETED_TOOLS = _EXPECTED_TOOLS - {"binary-ninja", "ghidra", "triton"}
_EXPECTED_UNAVAILABLE_TOOLS = {"binary-ninja", "ghidra", "triton"}
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def test_32_shard_report_covers_all_passes_and_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == summary["fixture_shard"] == {"count": 32, "index": 14}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and len(report["samples"]) == _EXPECTED_FIXTURE_COUNT
        and all(len(sample["passes"]) == _EXPECTED_PASS_COUNT for sample in report["samples"])
    )


def test_32_shard_report_records_applications_without_pass_errors() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["applied_pass_runs"] == _EXPECTED_APPLIED_RUNS
        and summary["error_pass_runs"] == summary["omitted_pass_runs"] == 0
        and sum(row["applied"] for row in summary["pass_status_counts"].values()) == _EXPECTED_APPLIED_RUNS
        and sum(row["error"] + row["omitted"] for row in summary["pass_status_counts"].values()) == 0
    )


def test_32_shard_report_accounts_for_every_analyzer_slot() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    analyzers = summary["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ROWS * len(_EXPECTED_TOOLS)
        and analyzers["completed_tool_runs"] == _EXPECTED_ROWS * len(_EXPECTED_COMPLETED_TOOLS)
        and analyzers["unavailable_tool_runs"] == _EXPECTED_ROWS * len(_EXPECTED_UNAVAILABLE_TOOLS)
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and analyzers["completed_tool_runs_by_tool"] == {tool: _EXPECTED_ROWS for tool in _EXPECTED_COMPLETED_TOOLS}
        and analyzers["unavailable_tool_runs_by_tool"] == {tool: _EXPECTED_ROWS for tool in _EXPECTED_UNAVAILABLE_TOOLS}
    )


def test_32_shard_summary_binds_source_commit_and_report_hash() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "acfc0995825d2fe5fdbcd56d7763508a4512f596"
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]["platform"] == "macOS arm64"
        and summary["execution_context"]["ida_pro"] == "9.5"
    )


def test_32_shard_summary_retains_angr_diagnostics_and_bounded_scope() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["observed_angr_diagnostics"]["unsupported_dirty_helpers"]
        == ["amd64g_dirtyhelper_IN", "amd64g_dirtyhelper_OUT"]
        and "do not prove semantic equivalence or general resistance" in summary["scope"]
    )


def test_32_shard_report_does_not_publish_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
