"""Regression checks for a completed adversarial analysis shard."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"
_SUMMARY_PATH = _DOCS / "protection-adversarial-shard-2026-11-15-43682458593-06-summary.json"
_REPORT_PATH = _DOCS / "protection-adversarial-shard-2026-11-15-43682458593-06.json"
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
_EXPECTED_WORKFLOW_RUN = 43_682_458_593
_EXPECTED_SAMPLE_COUNT = 1
_EXPECTED_PASS_COUNT = 22
_EXPECTED_TOOL_RUNS = _EXPECTED_PASS_COUNT * len(_EXPECTED_TOOLS)
_HOST_PATH_PREFIXES = (b"/home/", b"/runner/", b"/Users/", b"/private/", b"/opt/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _report() -> dict[str, object]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_adversarial_shard_manifest_binds_report_to_successful_job() -> None:
    summary = _summary()
    report_bytes = _REPORT_PATH.read_bytes()
    expect(
        summary["workflow_run"] == _EXPECTED_WORKFLOW_RUN
        and summary["source_commit"] == "13ac80258a5a51e0c872abe600bc04f52366ba0c"
        and summary["shard_job"] == {"id": 132_715_811_932, "name": "benchmark (6)", "conclusion": "success"}
        and summary["report"]
        == {
            "path": _REPORT_PATH.relative_to(_ROOT).as_posix(),
            "sha256": hashlib.sha256(report_bytes).hexdigest(),
            "size_bytes": len(report_bytes),
        }
    )


def test_adversarial_shard_records_expected_fixture_and_passes() -> None:
    summary = _summary()
    report = _report()
    expect(
        summary["fixture_shard"] == {"count": 32, "index": 6}
        and summary["sample_count"] == report["sample_count"] == _EXPECTED_SAMPLE_COUNT
        and summary["fixture"] == report["samples"][0]["original"] == "generated_signals_gcc-static-o2"
        and summary["pass_count"] == len(report["pass_names"]) == _EXPECTED_PASS_COUNT
    )


def test_adversarial_shard_observes_all_expected_analyzer_slots() -> None:
    summary = _summary()
    report_summary = _report()["summary"]
    expect(
        set(summary["expected_tools"]) == _EXPECTED_TOOLS
        and summary["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and summary["completed_tool_runs"] == report_summary["completed_tool_runs_by_tool"]
        and summary["unavailable_tool_runs"] == report_summary["unavailable_tool_runs_by_tool"]
    )


def test_adversarial_shard_preserves_tool_blockers_and_triton_budget() -> None:
    summary = _summary()
    expect(
        summary["completed_tool_runs"]
        == {
            "angr": _EXPECTED_PASS_COUNT,
            "custom": _EXPECTED_PASS_COUNT,
            "ghidra": _EXPECTED_PASS_COUNT,
            "objdump": _EXPECTED_PASS_COUNT,
            "radare2": _EXPECTED_PASS_COUNT,
            "triton": _EXPECTED_PASS_COUNT,
        }
        and summary["unavailable_tool_runs"]
        == {
            "binary-ninja": _EXPECTED_PASS_COUNT,
            "ida-pro": _EXPECTED_PASS_COUNT,
            "unicorn": _EXPECTED_PASS_COUNT,
        }
        and summary["missing_tool_runs"] == {}
        and summary["error_tool_runs"] == {}
        and summary["triton_instruction_budget_exhausted"] is True
    )


def test_adversarial_shard_keeps_release_gate_open_and_avoids_host_paths() -> None:
    summary = _summary()
    readiness = json.loads((_DOCS / "one-zero-readiness.json").read_text(encoding="utf-8"))
    report_bytes = _REPORT_PATH.read_bytes()
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _SUMMARY_PATH.relative_to(_ROOT).as_posix() in evidence
        and _REPORT_PATH.relative_to(_ROOT).as_posix() in evidence
        and summary["runtime_source_unchanged_since_source_commit"] is True
        and not any(prefix in report_bytes for prefix in _HOST_PATH_PREFIXES)
    )
