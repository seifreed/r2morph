"""Regression checks for the current-main local analyzer measurement."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-adversarial-local-codevirtualization-2026-11-15-cbc61cef.json"
_SUMMARY = _ROOT / "docs/protection-adversarial-local-codevirtualization-2026-11-15-cbc61cef-summary.json"
_SOURCE_COMMIT = "cbc61cefe352b94eb420e4b0d4acbd72f041840e"
_EXPECTED_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_EXPECTED_REPORT_SHA256 = "65ed82ee5c74696e65a7cd0981ac863a8cab873a3f7476ff355ce47c73ca1f5e"
_EXPECTED_ANALYZER_TOOL_RUNS = 9
_EXPECTED_COMPLETED_TOOL_RUNS = 7
_EXPECTED_UNAVAILABLE_TOOL_RUNS = 2
_EXPECTED_EXIT_CODE = 45
_EXPECTED_COMPLETED_TOOLS = (
    "angr",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "unicorn",
)
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def _report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_local_codevirtualization_report_is_bound_to_source_and_fixture() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["fixture"]["sha256"] == _EXPECTED_FIXTURE_SHA256
        and hashlib.sha256((_ROOT / summary["fixture"]["path"]).read_bytes()).hexdigest() == _EXPECTED_FIXTURE_SHA256
    )


def test_local_codevirtualization_report_records_applied_full_fixture_pass() -> None:
    report = _report()
    summary = _summary()

    expect(
        report["original"] == "elf_vm_arith_x86_64"
        and report["pass_names"] == ["CodeVirtualization"]
        and report["passes"][0]["status"] == summary["scope"]["pass_status"] == "applied"
        and report["passes"][0]["functions_virtualized"] == summary["scope"]["functions_virtualized"] == 1
        and report["passes"][0]["partial_virtualization"] == summary["scope"]["partial_virtualization"] == 0
        and report["passes"][0]["unsupported_functions"] == summary["scope"]["unsupported_functions"] == 0
    )


def test_local_codevirtualization_report_accounts_for_all_analyzer_slots() -> None:
    summary = _summary()
    analyzers = summary["analyzer_summary"]

    expect(
        analyzers["expected_tool_runs"] == _EXPECTED_ANALYZER_TOOL_RUNS
        and analyzers["completed_tool_runs"] == _EXPECTED_COMPLETED_TOOL_RUNS
        and analyzers["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_TOOL_RUNS
        and analyzers["error_tool_runs"] == analyzers["missing_tool_runs"] == 0
        and tuple(analyzers["completed_tools"]) == _EXPECTED_COMPLETED_TOOLS
    )


def test_local_codevirtualization_report_preserves_tool_limitations() -> None:
    unavailable = [tool for tool in _report()["tools"] if tool["status"] == "unavailable"]

    expect(
        {tool["tool"]: tool["reason"] for tool in unavailable}
        == {
            "binary-ninja": "analyzer license is unavailable",
            "triton": "module 'triton' is unavailable",
        }
    )


def test_local_codevirtualization_report_records_native_and_decompiler_observations() -> None:
    tools = {tool["tool"]: tool for tool in _report()["tools"]}

    expect(
        tools["unicorn"]["original"]["exit_code"] == tools["unicorn"]["protected"]["exit_code"] == _EXPECTED_EXIT_CODE
        and tools["ida-pro"]["original"]["decompiler_status"]
        == tools["ida-pro"]["protected"]["decompiler_status"]
        == "completed"
        and tools["ghidra"]["original"]["decompiler_status"]
        == tools["ghidra"]["protected"]["decompiler_status"]
        == "completed"
    )


def test_local_codevirtualization_evidence_does_not_close_general_readiness() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    paths = (f"docs/{_REPORT.name}", f"docs/{_SUMMARY.name}")

    expect(
        readiness["status"] == "blocked"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and all(path in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"] for path in paths)
    )


def test_local_codevirtualization_evidence_contains_no_host_paths() -> None:
    content = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS))
