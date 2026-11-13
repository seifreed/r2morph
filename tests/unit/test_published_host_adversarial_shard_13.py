"""Regression checks for the current-host CodeVirtualization shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json"
_SUMMARY = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json"
_EXPECTED_FIXTURES = 9
_EXPECTED_TOOL_COUNT = 9
_COMPLETED_TOOL_COUNT = 7
_UNAVAILABLE_TOOL_COUNT = _EXPECTED_TOOL_COUNT - _COMPLETED_TOOL_COUNT
_PATH_MARKERS = (
    "/Users/",
    "/Applications/",
    "/private/",
    f"{PurePosixPath('/', 'tmp').as_posix()}/",
    "/home/",
)


def test_current_host_shard_applies_code_virtualization_to_each_fixture() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 13}
        and report["sample_count"] == _EXPECTED_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["applied"] == _EXPECTED_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["errors"] == 0
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
        and report["pass_summary"]["CodeVirtualization"]["partial_virtualization"] == 0
    )


def test_current_host_shard_records_completed_and_unavailable_analyzers() -> None:
    report = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    summary = report["analyzer_summary"]

    expect(
        summary["expected_tool_runs"] == _EXPECTED_TOOL_COUNT * _EXPECTED_FIXTURES
        and summary["completed_tool_runs"] == _COMPLETED_TOOL_COUNT * _EXPECTED_FIXTURES
        and summary["error_tool_runs"] == 0
        and summary["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_COUNT * _EXPECTED_FIXTURES
        and summary["completed_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_FIXTURES
        and summary["completed_tool_runs_by_tool"]["ghidra"] == _EXPECTED_FIXTURES
        and summary["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": _EXPECTED_FIXTURES},
            "triton": {"module 'triton' is unavailable": _EXPECTED_FIXTURES},
        }
        and report["analyzer_diagnostics"]["angr_unsupported_dirty_helpers"]
        == ["amd64g_dirtyhelper_IN", "amd64g_dirtyhelper_OUT"]
    )


def test_current_host_shard_summary_binds_source_commit_and_raw_report() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "134af4ff210b594d46e9803299c2111cfbebfa90"
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


def test_current_host_shard_reports_do_not_expose_analyst_paths() -> None:
    reports = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in reports for marker in _PATH_MARKERS))
