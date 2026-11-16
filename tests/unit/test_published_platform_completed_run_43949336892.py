"""Pin the completed platform aggregate and keep its scope explicit."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-platform-completed-run-2026-11-16-43949336892.json"
_SUMMARY_PATH = _ROOT / "docs/platform-evidence-summary-43949336892.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_WORKFLOW_RUN_ID = 43949336892
_EXPECTED_CASES = {
    "macos-arm64": 37,
    "windows-pe": 18,
    "elf-arm-32": 6,
    "elf-arm64": 7,
    "elf-x86-32": 8,
}


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_platform_completion_manifest_pins_successful_workflow_and_aggregate() -> None:
    report = _read_json(_REPORT_PATH)
    summary_digest = hashlib.sha256(_SUMMARY_PATH.read_bytes()).hexdigest()

    expect(
        report["workflow_run_id"] == _WORKFLOW_RUN_ID
        and report["workflow_conclusion"] == "success"
        and report["workflow_jobs"] == {"total": 85, "successful": 85, "failed": 0, "cancelled": 0}
        and report["source_commit"] == "6c60d58d186fc7725465313b79ce488dee1ee0c4"
        and report["aggregate_summary_sha256"] == summary_digest
    )


def test_platform_aggregate_contains_all_required_cases_without_failures() -> None:
    summary = _read_json(_SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        summary["summary"]
        == {"complete_platforms": 5, "incomplete_platforms": [], "platform_count": 5, "status": "complete"}
        and {target: value["case_count"] for target, value in platforms.items()} == _EXPECTED_CASES
        and all(
            value["status"] == "complete"
            and value["failure_count"] == value["error_count"] == value["skipped_count"] == 0
            and value["missing_required_cases"] == []
            for value in platforms.values()
        )
    )


def test_bounded_platform_run_does_not_close_full_parity_readiness() -> None:
    report = _read_json(_REPORT_PATH)
    readiness = _read_json(_READINESS_PATH)
    criterion = readiness["criteria"]["cross_platform_parity"]
    report_reference = _REPORT_PATH.relative_to(_ROOT).as_posix()
    summary_reference = _SUMMARY_PATH.relative_to(_ROOT).as_posix()

    expect(
        report["totals"] == {"platforms": 5, "cases": 76, "passed": 76, "failures": 0, "errors": 0, "skipped": 0}
        and criterion["status"] == "open"
        and report_reference in criterion["evidence"]
        and summary_reference in criterion["evidence"]
    )
