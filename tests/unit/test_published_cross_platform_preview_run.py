"""Checks for the current five-platform preview reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-preview-run-2026-11-13-c45eb58e.json"
_SOURCE_COMMIT = "c45eb58e3de7cb5775ce84a202005196a127b970"
_RUN_ID = 43_340_083_394
_EXPECTED_COUNTS = {
    "macos_arm64": 35,
    "windows_pe": 17,
    "elf_arm32": 6,
    "elf_arm64": 7,
    "elf_x86_32": 8,
}
_EXPECTED_TOTAL = 73
_ZERO = 0
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _counts(report_path: Path) -> dict[str, int]:
    root = ElementTree.parse(report_path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    return {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }


def test_platform_preview_run_binds_reports_to_current_commit() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _RUN_ID
        and set(reports) == set(_EXPECTED_COUNTS)
        and all(
            row["sha256"] == hashlib.sha256((_ROOT / "docs" / row["report"]).read_bytes()).hexdigest()
            for row in reports.values()
        )
    )


def test_platform_preview_reports_match_successful_case_totals() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        all(
            _counts(_ROOT / "docs" / reports[name]["report"])
            == {"tests": count, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
            and reports[name]["tests"] == count
            and reports[name]["failures"] == reports[name]["errors"] == reports[name]["skipped"] == _ZERO
            for name, count in _EXPECTED_COUNTS.items()
        )
        and summary["totals"] == {"tests": _EXPECTED_TOTAL, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
    )


def test_platform_preview_reports_are_linked_without_closing_parity() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    required = [
        f"docs/{_SUMMARY_PATH.name}",
        *(f"docs/{row['report']}" for row in _summary()["platform_reports"].values()),
    ]

    expect(criterion["status"] == "open" and all(path in criterion["evidence"] for path in required))


def test_platform_preview_reports_do_not_expose_analyst_paths() -> None:
    paths = [_SUMMARY_PATH, *(_ROOT / "docs" / row["report"] for row in _summary()["platform_reports"].values())]
    content = "".join(path.read_text(encoding="utf-8") for path in paths)

    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES))
