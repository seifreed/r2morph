"""Pin selected passing preview jobs from the current-source differential run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/platform-differential-preview-2026-11-25-45517036412.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_WORKFLOW_RUN_ID = 45517036412
_EXPECTED_CASES = {
    "elf-x86-32": 8,
    "elf-arm32": 6,
    "elf-arm64": 7,
    "macos-arm64": 36,
    "macos-x86-64": 3,
    "windows-pe": 18,
}


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _junit_counts(path: Path) -> tuple[int, int, int, int]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    return tuple(
        sum(int(suite.attrib.get(name, "0")) for suite in suites) for name in ("tests", "failures", "errors", "skipped")
    )


def test_selected_preview_jobs_are_pinned_to_current_source_artifacts() -> None:
    report = _read_json(_REPORT_PATH)
    jobs = report["jobs"]

    expect(
        report["workflow_run_id"] == _WORKFLOW_RUN_ID
        and report["source_commit"] == "7a278ceaea15a8872a00b9c0d75ed6d2d8dddd6"
        and report["workflow_aggregate_conclusion_at_capture"] is None
        and {name: data["junit"]["tests"] for name, data in jobs.items()} == _EXPECTED_CASES
        and report["totals"]
        == {
            "platform_targets": 6,
            "cases": 78,
            "passed": 78,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        }
    )


def test_preview_junit_hashes_and_counts_match_the_published_manifest() -> None:
    report = _read_json(_REPORT_PATH)
    for job in report["jobs"].values():
        junit = job["junit"]
        path = _ROOT / junit["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        expect(
            digest == junit["sha256"]
            and _junit_counts(path) == (junit["tests"], junit["failures"], junit["errors"], junit["skipped"])
            and junit["passed"] == junit["tests"]
        )


def test_bounded_preview_snapshot_keeps_full_parity_gate_open() -> None:
    report = _read_json(_REPORT_PATH)
    readiness = _read_json(_READINESS_PATH)
    criterion = readiness["criteria"]["cross_platform_parity"]
    report_reference = _REPORT_PATH.relative_to(_ROOT).as_posix()

    expect(
        readiness["status"] == "blocked"
        and criterion["status"] == "open"
        and report_reference in criterion["evidence"]
        and "full pass-by-platform parity" in " ".join(report["limitations"])
    )
