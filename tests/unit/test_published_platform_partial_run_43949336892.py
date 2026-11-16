"""Verify the pinned partial cross-platform differential evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-platform-partial-run-2026-11-16-43949336892.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_WORKFLOW_RUN_ID = 43949336892
_EXPECTED_CASES = {
    "macos-arm64": 37,
    "windows-pe": 18,
    "elf-arm32": 6,
    "elf-arm64": 7,
    "elf-x86-32": 8,
}


def _load_report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def _junit_cases(path: Path) -> list[ElementTree.Element]:
    return ElementTree.parse(path).getroot().findall(".//testcase")


def test_platform_partial_report_binds_each_junit_artifact() -> None:
    report = _load_report()
    targets = report["targets"]

    expect(
        all(hashlib.sha256((_ROOT / row["report"]).read_bytes()).hexdigest() == row["sha256"] for row in targets)
        and report["source_commit"] == "6c60d58d186fc7725465313b79ce488dee1ee0c4"
        and report["workflow_run_id"] == _WORKFLOW_RUN_ID
    )


def test_platform_partial_report_records_all_seventy_six_cases() -> None:
    report = _load_report()
    targets = report["targets"]

    expect(
        {row["target"]: row["cases"] for row in targets} == _EXPECTED_CASES
        and all(
            row["cases"] == len(_junit_cases(_ROOT / row["report"])) == row["passed"]
            and row["failures"] == row["errors"] == row["skipped"] == 0
            for row in targets
        )
        and report["totals"]
        == {
            "targets": 5,
            "cases": 76,
            "passed": 76,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        }
    )


def test_platform_partial_report_keeps_full_parity_open() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["cross_platform_parity"]["evidence"]
    report_path = _REPORT.relative_to(_ROOT).as_posix()

    expect(
        readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and report_path in evidence
        and all(row["report"] in evidence for row in _load_report()["targets"])
        and "tests/unit/test_published_platform_partial_run_43949336892.py" in evidence
    )
