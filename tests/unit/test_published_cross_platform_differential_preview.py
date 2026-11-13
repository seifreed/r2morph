"""Contract checks for current bounded cross-platform preview artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-windows-pe-differential-preview-2026-11-13-92c6fef0.xml"
_SUMMARY = _ROOT / "docs/protection-windows-pe-differential-preview-2026-11-13-92c6fef0-summary.json"
_ARM32_REPORT = _ROOT / "docs/protection-elf-arm32-differential-preview-2026-11-13-92c6fef0.xml"
_ARM32_SUMMARY = _ROOT / "docs/protection-elf-arm32-differential-preview-2026-11-13-92c6fef0-summary.json"
_REPORT_NAME = _REPORT.name
_SUMMARY_NAME = _SUMMARY.name
_SOURCE_COMMIT = "92c6fef05c930b6822daf7fefd2bcbd6b082d26f"
_RUN_ID = 43_339_101_882
_EXPECTED_CASES = 17
_EXPECTED_ARM32_CASES = 6
_ZERO = 0
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _report_suites(path: Path = _REPORT) -> list[ElementTree.Element]:
    root = ElementTree.parse(path).getroot()
    return [root] if root.tag == "testsuite" else root.findall(".//testsuite")


def test_windows_pe_preview_binds_artifact_hash_to_current_commit() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _RUN_ID
        and summary["report"] == _REPORT_NAME
        and summary["report_sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and summary["platform"] == "Windows x86_64"
        and summary["format"] == "PE"
    )


def test_windows_pe_preview_records_only_successful_reported_cases() -> None:
    suites = _report_suites()
    observed = {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }

    expect(
        observed == {"tests": _EXPECTED_CASES, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
        and json.loads(_SUMMARY.read_text(encoding="utf-8"))["summary"]
        == {
            "tests": _EXPECTED_CASES,
            "failures": _ZERO,
            "errors": _ZERO,
            "skipped": _ZERO,
            "duration_seconds": 22.791,
        }
    )


def test_windows_pe_preview_covers_tier_one_native_observables() -> None:
    names = {case.attrib["name"] for suite in _report_suites() for case in suite.findall("testcase")}

    expect(
        {
            "test_tier1_pe_x86_pass_preserves_native_observables[instruction-substitution]",
            "test_tier1_pe_x86_pass_preserves_native_observables[register-substitution]",
            "test_tier1_pe_x86_pass_preserves_native_observables[instruction-expansion]",
            "test_tier1_pe_x86_pass_preserves_native_observables[constant-unfolding]",
            "test_tier1_pass_composition_pe_x86_64_preserves_native_execution",
        }.issubset(names)
    )


def test_arm32_preview_binds_successful_cases_to_current_commit() -> None:
    summary = json.loads(_ARM32_SUMMARY.read_text(encoding="utf-8"))
    suites = _report_suites(_ARM32_REPORT)
    observed = {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _RUN_ID
        and summary["report"] == _ARM32_REPORT.name
        and summary["report_sha256"] == hashlib.sha256(_ARM32_REPORT.read_bytes()).hexdigest()
        and summary["platform"] == "Linux x86_64 with QEMU ARM32"
        and summary["format"] == "ELF"
        and summary["architecture"] == "ARM32"
        and summary["summary"]
        == {
            "tests": _EXPECTED_ARM32_CASES,
            "failures": _ZERO,
            "errors": _ZERO,
            "skipped": _ZERO,
            "duration_seconds": 0.618,
        }
        and observed == {"tests": _EXPECTED_ARM32_CASES, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
    )


def test_windows_pe_preview_is_linked_without_claiming_parity() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    blockers = " ".join((_ROOT / "docs/release-blockers.md").read_text(encoding="utf-8").split())

    expect(
        criterion["status"] == "open"
        and f"docs/{_REPORT_NAME}" in criterion["evidence"]
        and f"docs/{_SUMMARY_NAME}" in criterion["evidence"]
        and f"docs/{_ARM32_REPORT.name}" in criterion["evidence"]
        and f"docs/{_ARM32_SUMMARY.name}" in criterion["evidence"]
        and "establish platform parity" in blockers
    )


def test_cross_platform_preview_reports_do_not_expose_analyst_paths() -> None:
    paths = (_REPORT, _SUMMARY, _ARM32_REPORT, _ARM32_SUMMARY)
    content = "".join(path.read_text(encoding="utf-8") for path in paths)

    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES))
