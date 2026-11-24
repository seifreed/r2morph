"""Verify hash-bound native Intel Mach-O smoke evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-macho-x86-64-native-2026-11-24-a4f4dcba.json"
_JUNIT = _ROOT / "docs/protection-macho-x86-64-native-2026-11-24-a4f4dcba.xml"
_TEST_FILE = _ROOT / "tests/integration/test_macho_x86_64_native.py"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_WORKFLOW_RUN_ID = 45480009561
_WORKFLOW_JOB_ID = 138750290310
_WORKFLOW_ARTIFACT_ID = 14961598946
_CASE_COUNT = 3
_CASES = {
    "test_macho_x86_64_instruction_substitution_preserves_native_observables",
    "test_macho_x86_64_register_substitution_preserves_native_observables",
    "test_macho_x86_64_string_obfuscation_preserves_native_observables",
}


def test_native_macho_x86_64_report_binds_source_and_junit() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["source_commit"] == "a4f4dcba12020cda4fa7717c4361c027d4b09081"
        and report["test_file"]["sha256"] == hashlib.sha256(_TEST_FILE.read_bytes()).hexdigest()
        and report["junit_report"]["sha256"] == hashlib.sha256(_JUNIT.read_bytes()).hexdigest()
        and report["workflow"]["run_id"] == _WORKFLOW_RUN_ID
        and report["workflow"]["job_id"] == _WORKFLOW_JOB_ID
        and report["workflow"]["artifact_id"] == _WORKFLOW_ARTIFACT_ID
    )


def test_native_macho_x86_64_junit_contains_three_passing_cases() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    suite = next(DefusedElementTree.parse(_JUNIT).getroot().iter("testsuite"))
    cases = list(suite.iter("testcase"))

    expect(
        report["host"] == {"os": "macOS", "architecture": "x86_64", "python": "3.12"}
        and report["junit_report"]["case_count"] == report["junit_report"]["passed_case_count"] == _CASE_COUNT
        and report["junit_report"]["failed_case_count"]
        == report["junit_report"]["error_case_count"]
        == report["junit_report"]["skipped_case_count"]
        == 0
        and suite.attrib["tests"] == "3"
        and suite.attrib["failures"] == suite.attrib["errors"] == suite.attrib["skipped"] == "0"
        and {case.attrib["name"] for case in cases} == _CASES
    )


def test_native_macho_x86_64_evidence_keeps_full_parity_gate_open() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]

    expect(
        criterion["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _JUNIT.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and Path(__file__).relative_to(_ROOT).as_posix() in criterion["evidence"]
        and report["limitations"]
    )
