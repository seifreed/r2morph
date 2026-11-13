"""Regression checks for the all-pass host analyzer shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json"
_EXPECTED_FIXTURE_COUNT = 9
_EXPECTED_PASS_COUNT = 22
_AVAILABLE_TOOL_COUNT = 7
_UNAVAILABLE_TOOL_COUNT = 2
_EXPECTED_APPLIED_PASS_RUNS = 17
_EXPECTED_NO_OP_PASS_RUNS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT - _EXPECTED_APPLIED_PASS_RUNS
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
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def test_current_host_shard_covers_all_passes_and_fixture_rows() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 13}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and summary["pass_status_counts"].keys() == set(report["pass_names"])
        and all(sum(counts.values()) == _EXPECTED_FIXTURE_COUNT for counts in summary["pass_status_counts"].values())
    )


def test_current_host_shard_reports_applied_noop_and_error_outcomes() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    statuses = summary["pass_status_counts"]

    expect(
        summary["applied_pass_runs"] == _EXPECTED_APPLIED_PASS_RUNS
        and summary["error_pass_runs"] == 0
        and summary["omitted_pass_runs"] == 0
        and sum(counts.get("applied", 0) for counts in statuses.values()) == _EXPECTED_APPLIED_PASS_RUNS
        and sum(counts.get("no-op", 0) for counts in statuses.values()) == _EXPECTED_NO_OP_PASS_RUNS
        and sum(counts.get("error", 0) for counts in statuses.values()) == 0
    )


def test_current_host_shard_records_available_and_unavailable_tool_slots() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    analyzers = summary["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT * len(_EXPECTED_TOOLS)
        and analyzers["completed_tool_runs"] == _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT * _AVAILABLE_TOOL_COUNT
        and analyzers["error_tool_runs"] == 0
        and analyzers["unavailable_tool_runs"]
        == _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT * _UNAVAILABLE_TOOL_COUNT
        and set(analyzers["completed_tool_runs_by_tool"]) == _EXPECTED_TOOLS - {"binary-ninja", "triton"}
        and set(analyzers["unavailable_tool_runs_by_tool"]) == {"binary-ninja", "triton"}
        and analyzers["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT},
            "triton": {"module 'triton' is unavailable": _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT},
        }
    )


def test_current_host_shard_binds_commit_and_raw_report_hash() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "24b306eee35a2ca4b0a03703a9960f3476f12294"
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]
        == {
            "platform": "macOS arm64",
            "python": "3.13.11",
            "ida_pro": "9.5",
            "ghidra": "12.2",
            "radare2": "6.2.6",
            "keystone": "available",
        }
    )


def test_current_host_shard_retains_angr_limitations() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["observed_log_diagnostics"]
        == {
            "angr_unsupported_dirty_helpers": ["amd64g_dirtyhelper_IN", "amd64g_dirtyhelper_OUT"],
            "angr_calling_convention": "Some generated/fixture functions had no inferred calling convention.",
        }
    )


def test_current_host_shard_reports_do_not_expose_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
