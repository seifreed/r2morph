"""Checks current-main five-platform differential preview evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-preview-run-2026-11-14-334f6626.json"
_SOURCE_COMMIT = "334f6626a38bfdbf933ecaf5afdc4312a6d61d98"
_WORKFLOW_RUN = 43_590_514_259
_EXPECTED_COUNTS = {
    "macos_arm64": 35,
    "windows_pe": 17,
    "elf_arm32": 6,
    "elf_arm64": 7,
    "elf_x86_32": 8,
}
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


def test_platform_preview_summary_binds_reports_to_current_main_run() -> None:
    summary = _summary()
    reports = summary["platform_reports"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and set(reports) == set(_EXPECTED_COUNTS)
        and all(
            report["sha256"] == hashlib.sha256((_ROOT / "docs" / report["report"]).read_bytes()).hexdigest()
            for report in reports.values()
        )
    )


def test_platform_preview_reports_have_expected_successful_case_counts() -> None:
    summary = _summary()

    expect(
        all(
            _counts(_ROOT / "docs" / summary["platform_reports"][platform]["report"])
            == {"tests": count, "failures": 0, "errors": 0, "skipped": 0}
            for platform, count in _EXPECTED_COUNTS.items()
        )
        and summary["totals"] == {"tests": 73, "failures": 0, "errors": 0, "skipped": 0}
    )


def test_platform_preview_evidence_does_not_close_full_parity() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]
    required = [
        f"docs/{_SUMMARY_PATH.name}",
        *(f"docs/{report['report']}" for report in _summary()["platform_reports"].values()),
    ]

    expect(
        criterion["status"] == "open"
        and _summary()["readiness"]["cross_platform_parity"] == "open"
        and all(path in criterion["evidence"] for path in required)
    )


def test_platform_preview_reports_do_not_expose_runner_host_or_paths() -> None:
    reports = _summary()["platform_reports"]
    paths = [_SUMMARY_PATH, *(_ROOT / "docs" / row["report"] for row in reports.values())]
    content = "".join(path.read_text(encoding="utf-8") for path in paths)

    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES))
