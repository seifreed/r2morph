"""Regression checks for the current-main local all-pass analyzer report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-adversarial-local-allpasses-2026-11-15-55369212.json"
_SUMMARY = _ROOT / "docs/protection-adversarial-local-allpasses-2026-11-15-55369212-summary.json"
_SOURCE_COMMIT = "553692129083620f1ce1827b3de32f1daec15ab2"
_EXPECTED_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_EXPECTED_REPORT_SHA256 = "79e7e68a093f2095ccf6209929c6a274e65f1c6d8b98fac41683cb3c87ffbd33"
_EXPECTED_COMPLETED_TOOLS = (
    "angr",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "unicorn",
)
_EXPECTED_PASS_RUNS = 22
_EXPECTED_APPLIED_PASS_RUNS = 2
_EXPECTED_NO_OP_PASS_RUNS = _EXPECTED_PASS_RUNS - _EXPECTED_APPLIED_PASS_RUNS
_EXPECTED_ANALYZER_RUNS = _EXPECTED_PASS_RUNS * 9
_EXPECTED_COMPLETED_ANALYZER_RUNS = 154
_EXPECTED_UNAVAILABLE_ANALYZER_RUNS = _EXPECTED_ANALYZER_RUNS - _EXPECTED_COMPLETED_ANALYZER_RUNS
_EXPECTED_ANALYZER_ROWS_PER_TOOL = _EXPECTED_PASS_RUNS
_EXPECTED_EXIT_CODE = 45
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def _report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_local_allpasses_report_is_bound_to_source_and_fixture() -> None:
    summary = _summary()
    fixture_path = _ROOT / summary["fixture"]["path"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == _EXPECTED_REPORT_SHA256
        and hashlib.sha256(_REPORT.read_bytes()).hexdigest() == _EXPECTED_REPORT_SHA256
        and summary["fixture"]["sha256"] == _EXPECTED_FIXTURE_SHA256
        and hashlib.sha256(fixture_path.read_bytes()).hexdigest() == _EXPECTED_FIXTURE_SHA256
    )


def test_local_allpasses_report_covers_every_named_pass_row() -> None:
    report = _report()
    summary = _summary()
    counts = summary["pass_summary"]

    expect(
        len(report["pass_names"]) == len(report["passes"]) == counts["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and sum(counts[key] for key in ("applied_pass_runs", "no_op_pass_runs")) == _EXPECTED_PASS_RUNS
        and counts["applied_pass_runs"] == _EXPECTED_APPLIED_PASS_RUNS
        and counts["no_op_pass_runs"] == _EXPECTED_NO_OP_PASS_RUNS
        and counts["error_pass_runs"] == counts["omitted_pass_runs"] == 0
        and [row["pass_name"] for row in report["passes"] if row["status"] == "applied"]
        == ["CodeVirtualization", "InstructionSubstitution"]
    )


def test_local_allpasses_report_accounts_for_all_analyzer_rows() -> None:
    analyzers = _summary()["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ANALYZER_RUNS
        and analyzers["completed_tool_runs"] == _EXPECTED_COMPLETED_ANALYZER_RUNS
        and analyzers["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_ANALYZER_RUNS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and tuple(analyzers["completed_tools"]) == _EXPECTED_COMPLETED_TOOLS
    )


def test_local_allpasses_report_records_exact_unavailable_analyzers() -> None:
    analyzers = _summary()["analyzer_summary"]

    expect(
        analyzers["unavailable_tool_runs_by_tool"]
        == {"binary-ninja": _EXPECTED_ANALYZER_ROWS_PER_TOOL, "triton": _EXPECTED_ANALYZER_ROWS_PER_TOOL}
        and analyzers["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": "analyzer license is unavailable",
            "triton": "module 'triton' is unavailable",
        }
    )


def test_local_allpasses_report_records_matched_unicorn_exit_codes() -> None:
    runs = {row["pass_name"]: row for row in _report()["tools"] if row["tool"] == "unicorn"}

    expect(
        len(runs) == _EXPECTED_PASS_RUNS
        and all(
            row["status"] == "completed"
            and row["original"]["exit_code"] == row["protected"]["exit_code"] == _EXPECTED_EXIT_CODE
            for row in runs.values()
        )
    )


def test_local_allpasses_readiness_keeps_general_claims_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    paths = (f"docs/{_REPORT.name}", f"docs/{_SUMMARY.name}")

    expect(
        readiness["status"] == "blocked"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and all(path in evidence for path in paths)
    )


def test_local_allpasses_report_contains_no_host_paths() -> None:
    content = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS))
