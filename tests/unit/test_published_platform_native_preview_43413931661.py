"""Checks the current-main native platform preview evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-native-preview-run-2026-11-13-43413931661.json"
_SOURCE_COMMIT = "6fd356091da722d95dbc0f51463629cb10ce41ed"
_RUN_ID = 43_413_931_661
_EXPECTED_COUNTS = {"macos_arm64": 35, "windows_pe": 17}
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


def test_current_main_platform_preview_binds_reports_to_run() -> None:
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


def test_current_main_platform_preview_has_zero_failures_and_skips() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        all(
            _counts(_ROOT / "docs" / reports[name]["report"])
            == {"tests": count, "failures": 0, "errors": 0, "skipped": 0}
            for name, count in _EXPECTED_COUNTS.items()
        )
        and summary["totals"] == {"tests": 52, "failures": 0, "errors": 0, "skipped": 0}
    )


def test_current_main_platform_preview_keeps_full_parity_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    required = [
        f"docs/{_SUMMARY_PATH.name}",
        *(f"docs/{row['report']}" for row in _summary()["platform_reports"].values()),
    ]

    expect(criterion["status"] == "open" and all(path in criterion["evidence"] for path in required))


def test_current_main_platform_preview_does_not_publish_host_paths() -> None:
    reports = _summary()["platform_reports"]
    paths = [_SUMMARY_PATH, *(_ROOT / "docs" / row["report"] for row in reports.values())]
    content = "".join(path.read_text(encoding="utf-8") for path in paths)

    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES))
