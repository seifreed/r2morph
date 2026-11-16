"""Pin a current-main local multi-analyzer measurement."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = "docs/protection-adversarial-current-main-local-2026-11-16-e86a7829.json"
_SUMMARY_PATH = "docs/protection-adversarial-current-main-local-2026-11-16-e86a7829-summary.json"
_SOURCE_COMMIT = "e86a782959b50282cb41c8d851eba4c1e8de0965"
_FIXTURE_PATH = "fixtures/dataset/elf_vm_arith_x86_64"
_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_REPORT_SHA256 = "0a0ac3e4b32ab645e5ea1599b4d5bb7a8400de9bb7a893cb6d404991cc4dac90"
_EXPECTED_ANALYZER_RUNS = 9
_EXPECTED_COMPLETED_RUNS = 8
_EXPECTED_UNAVAILABLE_RUNS = _EXPECTED_ANALYZER_RUNS - _EXPECTED_COMPLETED_RUNS
_EXPECTED_EXIT_CODE = 45
_ZERO = 0


def _json(path: str) -> dict[str, object]:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def test_current_main_adversarial_report_is_bound_to_source_and_fixture() -> None:
    summary = _json(_SUMMARY_PATH)
    report_path = _ROOT / _REPORT_PATH
    fixture_path = _ROOT / _FIXTURE_PATH

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT_PATH
        and summary["source_report_sha256"] == _REPORT_SHA256
        and hashlib.sha256(report_path.read_bytes()).hexdigest() == _REPORT_SHA256
        and summary["fixture"]["sha256"] == _FIXTURE_SHA256
        and hashlib.sha256(fixture_path.read_bytes()).hexdigest() == _FIXTURE_SHA256
    )


def test_current_main_adversarial_report_records_applied_virtualization() -> None:
    report = _json(_REPORT_PATH)
    summary = _json(_SUMMARY_PATH)

    expect(
        report["original"] == "elf_vm_arith_x86_64"
        and report["pass_names"] == ["CodeVirtualization"]
        and report["passes"][0]["status"] == summary["scope"]["pass_status"] == "applied"
        and report["passes"][0]["functions_virtualized"] == summary["scope"]["functions_virtualized"] == 1
        and report["passes"][0]["partial_virtualization"] == summary["scope"]["partial_virtualization"] == _ZERO
        and report["passes"][0]["unsupported_functions"] == summary["scope"]["unsupported_functions"] == _ZERO
    )


def test_current_main_adversarial_report_accounts_for_all_analyzer_slots() -> None:
    analyzers = _json(_SUMMARY_PATH)["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ANALYZER_RUNS
        and analyzers["completed_tool_runs"] == _EXPECTED_COMPLETED_RUNS
        and analyzers["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_RUNS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == _ZERO
        and analyzers["unavailable_reasons_by_tool"] == {"binary-ninja": "analyzer license is unavailable"}
        and {"triton", "unicorn", "ida-pro", "ghidra", "angr"}.issubset(set(analyzers["completed_tools"]))
    )


def test_current_main_adversarial_report_records_semantic_and_decompiler_results() -> None:
    report = _json(_REPORT_PATH)
    summary = _json(_SUMMARY_PATH)
    tools = {row["tool"]: row for row in report["tools"]}

    expect(
        tools["unicorn"]["original"]["exit_code"] == tools["unicorn"]["protected"]["exit_code"] == _EXPECTED_EXIT_CODE
        and tools["triton"]["status"] == "completed"
        and tools["triton"]["protected"]["semantically_supported_instructions"]
        == summary["observations"]["triton_protected_semantically_supported"]
        and tools["ida-pro"]["protected"]["decompiler_status"] == "completed"
        and tools["ghidra"]["protected"]["decompiler_status"] == "completed"
    )


def test_current_main_adversarial_report_keeps_release_gates_open() -> None:
    readiness = _json("docs/one-zero-readiness.json")

    expect(
        readiness["status"] == "blocked"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _SUMMARY_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
    )


def test_current_main_adversarial_report_contains_no_host_paths() -> None:
    content = (_ROOT / _REPORT_PATH).read_text(encoding="utf-8")
    content += (_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8")

    expect(not any(marker in content for marker in ("/Users/", "/Applications/", "/private/", "/home/")))
