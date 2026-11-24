"""Verify the hash-bound current-main native ARM64 string smoke evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-macho-arm64-string-2026-11-24-a4f4dcba.json"
_JUNIT = _ROOT / "docs/protection-macho-arm64-string-2026-11-24-a4f4dcba.xml"
_TEST_FILE = _ROOT / "tests/integration/test_macho_arm64_string_obfuscation.py"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_CASE = "test_macho_arm64_string_obfuscation_preserves_native_observables"


def test_native_macho_string_report_binds_source_and_inputs() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["source_commit"] == "a4f4dcba12020cda4fa7717c4361c027d4b09081"
        and report["test_file"]["sha256"] == hashlib.sha256(_TEST_FILE.read_bytes()).hexdigest()
        and report["junit_report"]["sha256"] == hashlib.sha256(_JUNIT.read_bytes()).hexdigest()
        and report["junit_report"]["path"] == _JUNIT.name
    )


def test_native_macho_string_report_matches_passing_junit_case() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    suite = next(DefusedElementTree.parse(_JUNIT).getroot().iter("testsuite"))
    case = next(suite.iter("testcase"))

    expect(
        report["host"] == {"os": "macOS", "architecture": "arm64", "python": "3.12"}
        and report["junit_report"]["case_count"] == report["junit_report"]["passed_case_count"] == 1
        and report["junit_report"]["failed_case_count"] == report["junit_report"]["skipped_case_count"] == 0
        and suite.attrib["tests"] == "1"
        and suite.attrib["failures"] == suite.attrib["errors"] == suite.attrib["skipped"] == "0"
        and case.attrib["name"] == _TEST_CASE
    )


def test_native_macho_string_report_keeps_full_parity_gate_open() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    evidence = criterion["evidence"]

    expect(
        criterion["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in evidence
        and _JUNIT.relative_to(_ROOT).as_posix() in evidence
        and Path(__file__).relative_to(_ROOT).as_posix() in evidence
    )
