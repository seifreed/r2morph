"""Pin the complete six-slice platform preview from differential run 45531042241."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-preview-2026-11-25-45531042241/summary.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_RUN_ID = 45531042241
_SOURCE_COMMIT = "6756d0b636ac3a64b4a96564c2671c1182f1acd2"
_TARGET_CASES = {
    "elf-arm32": 6,
    "elf-arm64": 7,
    "elf-x86-32": 8,
    "macos-arm64": 36,
    "macos-x86-64": 3,
    "windows-pe": 18,
}
_HOST_MARKERS = ("hostname=", "runnervm", "/Users/", "/Applications/", "/private/", "/home/")


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_all_six_preview_slices_are_bound_to_the_current_source_run() -> None:
    report = _read_json(_SUMMARY_PATH)
    workflow = report["workflow"]
    totals = report["summary"]
    reports = report["reports"]

    expect(
        report["schema_version"] == 1
        and workflow["run_id"] == _RUN_ID
        and report["source_commit"] == _SOURCE_COMMIT
        and workflow["job_counts_at_capture"]
        == {"total": 83, "completed_success": 20, "completed_failure": 0, "in_progress": 4, "queued": 59}
        and {row["target"]: row["case_count"] for row in reports} == _TARGET_CASES
        and totals
        == {
            "platform_slices": 6,
            "case_count": 78,
            "passed_case_count": 78,
            "failed_case_count": 0,
            "error_case_count": 0,
            "skipped_case_count": 0,
        }
    )


def test_sanitized_junit_reports_match_hashes_and_case_counts() -> None:
    report = _read_json(_SUMMARY_PATH)
    for row in report["reports"]:
        path = _ROOT / row["report"]
        content = path.read_bytes()
        xml = ElementTree.fromstring(content)
        cases = xml.findall(".//testcase")

        expect(
            hashlib.sha256(content).hexdigest() == row["report_sha256"]
            and len(cases) == row["case_count"]
            and not xml.findall(".//failure")
            and not xml.findall(".//error")
            and not xml.findall(".//skipped")
            and not any(marker in content.decode("utf-8") for marker in _HOST_MARKERS)
            and isinstance(row["artifact_digest"], str)
            and row["artifact_digest"].startswith("sha256:")
        )


def test_bounded_platform_preview_keeps_global_parity_gate_open() -> None:
    report = _read_json(_SUMMARY_PATH)
    readiness = _read_json(_READINESS_PATH)
    criterion = readiness["criteria"]["cross_platform_parity"]
    report_reference = _SUMMARY_PATH.relative_to(_ROOT).as_posix()

    expect(
        criterion["status"] == "open"
        and report_reference in criterion["evidence"]
        and all(row["report"] in criterion["evidence"] for row in report["reports"])
        and "every pass on every platform" in " ".join(report["limitations"])
        and str(_RUN_ID) in (_ROOT / "README.md").read_text(encoding="utf-8")
    )
