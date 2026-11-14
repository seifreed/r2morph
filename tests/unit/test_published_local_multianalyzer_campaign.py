"""Regression checks for the bounded local multi-analyzer campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_RAW_REPORT = _ROOT / "docs" / "protection-adversarial-local-multianalyzer-2026-11-14-87af8f71.json"
_SUMMARY = _ROOT / "docs" / "protection-adversarial-local-multianalyzer-2026-11-14-87af8f71-summary.json"
_FIXTURE = _ROOT / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_IDA_DECOMPILER_LINES_DELTA = 26
_IDA_DECOMPILER_BYTES_DELTA = 939
_GHIDRA_DECOMPILER_LINES_DELTA = 35
_GHIDRA_DECOMPILER_BYTES_DELTA = 607
_EXPECTED_PASS_COUNT = 22
_APPLIED_PASS_COUNT = 2
_NO_OP_PASS_COUNT = 20
_EXPECTED_ANALYZER_RUNS = 198
_COMPLETED_ANALYZER_RUNS = 176
_RUNS_PER_ANALYZER = 22
_TRITON_DECODED_INSTRUCTIONS = 3861
_TRITON_SUPPORTED_INSTRUCTIONS = 3850
_TRITON_INVALID_BYTES = 29


def test_multianalyzer_summary_binds_report_and_fixture_hashes() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "87af8f7157a0d398107248763508081566dbc712"
        and summary["provenance"] == "local-source-tree"
        and summary["report_sha256"] == hashlib.sha256(_RAW_REPORT.read_bytes()).hexdigest()
        and summary["fixture_sha256"] == hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()
    )


def test_multianalyzer_campaign_records_fully_applied_virtualization() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["fixture"] == "elf_vm_arith_x86_64"
        and summary["pass_count"] == _EXPECTED_PASS_COUNT
        and summary["pass_status_counts"]["applied"] == _APPLIED_PASS_COUNT
        and summary["pass_status_counts"]["no-op"] == _NO_OP_PASS_COUNT
        and next(row for row in summary["passes"] if row["name"] == "CodeVirtualization")
        == {
            "name": "CodeVirtualization",
            "status": "applied",
            "mutations_applied": 0,
            "functions_virtualized": 1,
            "partial_virtualization": 0,
            "unsupported_functions": 0,
        }
    )


def test_multianalyzer_campaign_records_real_ida_and_ghidra_deltas() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["analyzers"]["ida-pro"]["completed"] == _RUNS_PER_ANALYZER
        and summary["applied_code_virtualization_deltas"]["ida-pro"]["protected"]["decompiler_lines"]
        - summary["applied_code_virtualization_deltas"]["ida-pro"]["original"]["decompiler_lines"]
        == _IDA_DECOMPILER_LINES_DELTA
        and summary["applied_code_virtualization_deltas"]["ida-pro"]["protected"]["decompiler_bytes"]
        - summary["applied_code_virtualization_deltas"]["ida-pro"]["original"]["decompiler_bytes"]
        == _IDA_DECOMPILER_BYTES_DELTA
        and summary["analyzers"]["ghidra"]["completed"] == _RUNS_PER_ANALYZER
        and summary["applied_code_virtualization_deltas"]["ghidra"]["protected"]["decompiler_lines"]
        - summary["applied_code_virtualization_deltas"]["ghidra"]["original"]["decompiler_lines"]
        == _GHIDRA_DECOMPILER_LINES_DELTA
        and summary["applied_code_virtualization_deltas"]["ghidra"]["protected"]["decompiler_bytes"]
        - summary["applied_code_virtualization_deltas"]["ghidra"]["original"]["decompiler_bytes"]
        == _GHIDRA_DECOMPILER_BYTES_DELTA
    )


def test_multianalyzer_campaign_preserves_unavailable_analyzer_rows() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["tool_coverage"]["expected_runs"] == _EXPECTED_ANALYZER_RUNS
        and summary["tool_coverage"]["completed_runs"] == _COMPLETED_ANALYZER_RUNS
        and summary["tool_coverage"]["unavailable_tools"] == ["binary-ninja"]
        and summary["tool_coverage"]["error_runs"] == 0
        and summary["analyzers"]["binary-ninja"]["unavailable"] == _RUNS_PER_ANALYZER
        and summary["analyzers"]["binary-ninja"]["unavailable_reasons"]
        == {"analyzer license is unavailable": _RUNS_PER_ANALYZER}
        and summary["analyzers"]["triton"]["completed"] == _RUNS_PER_ANALYZER
        and summary["triton_code_virtualization"]["decoded_instructions"] == _TRITON_DECODED_INSTRUCTIONS
        and summary["triton_code_virtualization"]["semantically_supported_instructions"]
        == _TRITON_SUPPORTED_INSTRUCTIONS
        and summary["triton_code_virtualization"]["invalid_bytes"] == _TRITON_INVALID_BYTES
        and not summary["triton_code_virtualization"]["instruction_budget_exhausted"]
    )


def test_multianalyzer_campaign_keeps_general_release_criteria_open() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))

    expect(
        summary["release_criteria"]["all_named_adversarial_analyzers"] == "open"
        and summary["release_criteria"]["published_resistance_results"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_multianalyzer_campaign_does_not_expose_analyst_paths() -> None:
    report_text = _RAW_REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(prefix in report_text for prefix in _HOST_PATH_PREFIXES))
