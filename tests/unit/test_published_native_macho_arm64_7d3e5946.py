"""Verify the published native Mach-O ARM64 differential smoke evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-platform-macos-arm64-local-2026-11-16-7d3e5946.json"
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_FIXTURE = _ROOT / "fixtures" / "dataset" / "macho_arm64"
_TEST_FILE = _ROOT / "tests" / "integration" / "test_mutation_nop_insertion_arm64.py"
_EXPECTED_CASES = (
    "test_nop_insertion_arm64_preserves_native_output",
    "test_constant_unfolding_arm64_preserves_native_output",
    "test_instruction_expansion_arm64_preserves_native_output",
    "test_instruction_substitution_arm64_preserves_native_output",
    "test_nop_then_instruction_substitution_arm64_preserves_native_output",
)
_DESELECTED_CASE_COUNT = 7


def test_native_macho_arm64_report_binds_current_source_and_inputs() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    fixture_hash = hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()
    test_hash = hashlib.sha256(_TEST_FILE.read_bytes()).hexdigest()

    expect(
        report["source_commit"] == "7d3e5946a41fd5578e01ecef680bbf7e2ecf6043"
        and report["fixture"]["sha256"] == fixture_hash
        and report["test_file"]["sha256"] == test_hash
    )


def test_native_macho_arm64_report_records_only_passed_selected_cases() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["host"] == {"os": "macOS", "architecture": "arm64", "python": "3.14.10", "clang": "23.1.5"}
        and tuple(case["name"] for case in report["cases"]) == _EXPECTED_CASES
        and all(case["outcome"] == "passed" for case in report["cases"])
        and report["selected_case_count"] == report["passed_case_count"] == len(_EXPECTED_CASES)
        and report["failed_case_count"] == 0
        and report["deselected_case_count"] == _DESELECTED_CASE_COUNT
    )


def test_native_macho_arm64_evidence_keeps_full_platform_parity_open() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))

    expect(
        readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
    )
