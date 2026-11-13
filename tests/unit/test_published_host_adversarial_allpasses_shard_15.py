"""Regression checks for the fifteenth all-pass host analyzer shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15-summary.json"
_EXPECTED_FIXTURE_COUNT = 10
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS = _EXPECTED_FIXTURE_COUNT * _EXPECTED_PASS_COUNT
_EXPECTED_APPLIED_RUNS = 16
_EXPECTED_NO_OP_RUNS = _EXPECTED_ROWS - _EXPECTED_APPLIED_RUNS
_EXPECTED_COMPLETED_TOOL_RUNS = 1518
_EXPECTED_UNAVAILABLE_TOOL_RUNS = 462
_EXPECTED_UNICORN_COMPLETED_RUNS = 198
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def test_fifteenth_host_shard_covers_all_passes_and_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 15}
        and report["sample_count"] == summary["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == len(summary["pass_names"]) == _EXPECTED_PASS_COUNT
        and len(report["samples"]) == _EXPECTED_FIXTURE_COUNT
        and all(len(sample["passes"]) == _EXPECTED_PASS_COUNT for sample in report["samples"])
    )


def test_fifteenth_host_shard_has_no_pass_errors_or_omissions() -> None:
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


def test_fifteenth_host_shard_accounts_for_analyzer_availability() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    analyzers = summary["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ROWS * 9
        and analyzers["completed_tool_runs"] == _EXPECTED_COMPLETED_TOOL_RUNS
        and analyzers["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_TOOL_RUNS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and analyzers["completed_tool_runs_by_tool"]["unicorn"] == _EXPECTED_UNICORN_COMPLETED_RUNS
        and analyzers["unavailable_tool_runs_by_tool"] == {"binary-ninja": 220, "triton": 220, "unicorn": 22}
        and analyzers["unavailable_reasons_by_tool"]["unicorn"]
        == {"the installed x86 emulator does not support an instruction in this fixture": 22}
    )


def test_fifteenth_host_shard_binds_source_and_report_digest() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "5806a27d3689a2f3fe2d647be25f74eaa3265a9a"
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["execution_context"]["platform"] == "macOS arm64"
        and summary["execution_context"]["python"] == "3.13.11"
    )


def test_fifteenth_host_shard_preserves_diagnostic_limits_and_scope() -> None:
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


def test_fifteenth_host_shard_does_not_publish_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
