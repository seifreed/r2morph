"""Checks the bounded current-main VM call analysis evidence."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-current-main-vm-call-analysis-2026-11-15.json"
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_REPORT_REFERENCE = "docs/protection-current-main-vm-call-analysis-2026-11-15.json"
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_EXPECTED_ORIGINAL_FUNCTION_COUNT = 2
_EXPECTED_PROTECTED_FUNCTION_COUNT = 3
_EXPECTED_LIMITATION_COUNT = 5


def test_current_vm_call_analysis_binds_source_and_binary_hashes() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["source_commit"] == "47dcc6a24f644c42ffe5e540a7d9aadb91df2191"
        and report["fixture"] == "elf_vm_call_x86_64"
        and report["transformation"]["original_sha256"]
        == "a74b830c273088e2b58458e5227b839d0a1e07b422e34dfa6c42db5e10e08754"
        and report["transformation"]["protected_sha256"]
        == "efbbc8346dd96b1cc17fabb7d60fc3a13f6df4488f68caa1cdede9a5e699665c"
    )


def test_current_vm_call_analysis_records_applied_structurally_valid_pass() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    transformation = report["transformation"]

    expect(
        transformation["name"] == "CodeVirtualization"
        and transformation["status"] == "applied"
        and transformation["functions_virtualized"] == 1
        and transformation["partial_virtualization"] == 0
        and transformation["unsupported_functions"] == 0
        and transformation["structural_validation"] == "passed"
    )


def test_current_vm_call_analysis_preserves_decompiler_failures_and_limits() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["ida_pro"]["analysis_status"] == "completed"
        and report["ida_pro"]["original"]["function_count"] == _EXPECTED_ORIGINAL_FUNCTION_COUNT
        and report["ida_pro"]["protected"]["function_count"] == _EXPECTED_PROTECTED_FUNCTION_COUNT
        and report["ida_pro"]["protected"]["decompilation"]["0x402000"] == "no_function"
        and len(report["limitations"]) == _EXPECTED_LIMITATION_COUNT
    )


def test_current_vm_call_analysis_does_not_publish_host_paths() -> None:
    report_text = _REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report_text for prefix in _HOST_PATH_PREFIXES))


def test_current_vm_call_analysis_is_registered_without_closing_global_gate() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(criterion["status"] == "open" and _REPORT_REFERENCE in criterion["evidence"])
