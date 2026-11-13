"""Regression checks for the fourteenth all-pass host analyzer shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14-summary.json"
_EXPECTED_FIXTURE_COUNT = 11
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT
_EXPECTED_APPLIED_RUNS = 30
_EXPECTED_NO_OP_RUNS = _EXPECTED_ROWS - _EXPECTED_APPLIED_RUNS
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


def test_fourteenth_host_shard_covers_all_passes_and_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 14}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and len(report["samples"]) == _EXPECTED_FIXTURE_COUNT
        and all(len(sample["passes"]) == _EXPECTED_PASS_COUNT for sample in report["samples"])
    )


def test_fourteenth_host_shard_has_no_pass_errors_or_omissions() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["applied_pass_runs"] == _EXPECTED_APPLIED_RUNS
        and summary["error_pass_runs"] == 0
        and summary["omitted_pass_runs"] == 0
        and sum(counts["applied"] for counts in summary["pass_status_counts"].values()) == _EXPECTED_APPLIED_RUNS
        and sum(counts["no-op"] for counts in summary["pass_status_counts"].values()) == _EXPECTED_NO_OP_RUNS
        and sum(counts["error"] for counts in summary["pass_status_counts"].values()) == 0
        and sum(counts["omitted"] for counts in summary["pass_status_counts"].values()) == 0
    )


def test_fourteenth_host_shard_accounts_for_every_analyzer_slot() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    analyzers = summary["analyzer_summary"]

    expect(
        set(analyzers["completed_tool_runs_by_tool"]) == _EXPECTED_TOOLS - {"binary-ninja", "triton"}
        and all(count == _EXPECTED_ROWS for count in analyzers["completed_tool_runs_by_tool"].values())
        and analyzers["unavailable_tool_runs_by_tool"] == {"binary-ninja": _EXPECTED_ROWS, "triton": _EXPECTED_ROWS}
        and analyzers["completed_tool_runs"] + analyzers["unavailable_tool_runs"] == analyzers["expected_tool_runs"]
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
    )


def test_fourteenth_host_shard_binds_source_and_report_digest() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "2c9be637f3e019b64a7d194e2d27d2ea7a243d28"
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]["platform"] == "macOS arm64"
        and summary["execution_context"]["python"] == "3.13.11"
    )


def test_fourteenth_host_shard_retains_analyzer_limitations_and_scope() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["observed_angr_diagnostics"]["unsupported_dirty_helpers"]
        == ["amd64g_dirtyhelper_IN", "amd64g_dirtyhelper_OUT"]
        and summary["scope"]
        == (
            "One repository-fixture shard only. Analyzer metrics are bounded structural observations "
            "and do not prove semantic equivalence or general resistance."
        )
    )


def test_fourteenth_host_shard_does_not_publish_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
