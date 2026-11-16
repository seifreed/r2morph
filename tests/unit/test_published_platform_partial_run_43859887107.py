"""Verify the completed platform evidence from an in-progress campaign."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-partial-run-2026-11-16-43859887107.json"
_WORKFLOW_RUN = 43_859_887_107
_SOURCE_COMMIT = "3857682ca05ebad1ad1b2aa84b4689c0090ea8c5"
_TOTAL_TEST_COUNT = 74
_EXPECTED_COUNTS = {
    "macos_arm64": 35,
    "windows_pe": 18,
    "elf_arm32": 6,
    "elf_arm64": 7,
    "elf_x86_32": 8,
}
_HOST_MARKERS = ("runnervm", "sjc22-", "/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _counts(report_path: Path) -> dict[str, int]:
    root = ElementTree.parse(report_path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    return {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }


def test_platform_partial_summary_binds_workflow_and_sanitized_reports() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and set(reports) == set(_EXPECTED_COUNTS)
        and all(
            re.fullmatch(r"[0-9a-f]{64}", report["original_report_sha256"])
            and report["report_sha256"] == hashlib.sha256((_ROOT / "docs" / report["report"]).read_bytes()).hexdigest()
            for report in reports.values()
        )
    )


def test_platform_partial_reports_record_only_completed_successes() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        all(
            _counts(_ROOT / "docs" / reports[platform]["report"])
            == {"tests": count, "failures": 0, "errors": 0, "skipped": 0}
            for platform, count in _EXPECTED_COUNTS.items()
        )
        and summary["totals"] == {"tests": _TOTAL_TEST_COUNT, "failures": 0, "errors": 0, "skipped": 0}
        and summary["workflow_state_at_collection"]["failures"] == 0
    )


def test_platform_partial_reports_redact_runner_hosts_and_local_paths() -> None:
    report_paths = [_ROOT / "docs" / report["report"] for report in _summary()["platform_reports"].values()]
    content = "".join(path.read_text(encoding="utf-8") for path in report_paths)

    expect(not any(marker in content for marker in _HOST_MARKERS) and "hostname=" not in content)


def test_platform_partial_evidence_keeps_full_parity_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    evidence_paths = [
        f"docs/{_SUMMARY_PATH.name}",
        *(f"docs/{report['report']}" for report in _summary()["platform_reports"].values()),
    ]

    expect(
        criterion["status"] == "open"
        and _summary()["totals"]["tests"] == _TOTAL_TEST_COUNT
        and all(path in criterion["evidence"] for path in evidence_paths)
    )
