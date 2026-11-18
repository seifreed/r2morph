"""Pin bounded differential evidence from the current main workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/differential-run-2026-11-18-44213229027-summary.json"
_RUN_ID = 44213229027
_SOURCE_COMMIT = "1cf52005310a527b86c68b4ff713ce248f1432d7"
_ZERO = 0
_JOB_COUNT = 85
_CORE_RUN_COUNT = 5540
_EXTENDED_RUN_COUNT = 7572
_VM_TEST_COUNT = 2450
_COMPOSITION_TEST_COUNT = 1288
_FUZZ_CASE_COUNT = 1728
_CROSS_FORMAT_REPORT_COUNT = 29
_CROSS_FORMAT_TEST_COUNT = 2146
_CROSS_FORMAT_SKIPPED_COUNT = 290


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def test_published_differential_workflow_44213229027_completed_on_current_source() -> None:
    workflow = _summary()["workflow"]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["status"] == "completed"
        and workflow["conclusion"] == "success"
        and workflow["jobs_completed"] == _JOB_COUNT
    )


def test_published_differential_workflow_44213229027_records_zero_campaign_failures() -> None:
    report = _summary()
    core = report["differential_corpus"]
    extended = report["extended_maturity"]
    supplemental = report["supplemental_campaigns"]

    expect(
        core["classified_runs"] == core["successful_runs"] == _CORE_RUN_COUNT
        and core["failed_runs"] == core["error_runs"] == core["complete_evidence_missing_runs"] == _ZERO
        and core["applied_runs"] + core["omitted_ineligible_runs"] == core["classified_runs"]
        and extended["classified_runs"] == extended["successful_runs"] == _EXTENDED_RUN_COUNT
        and extended["failed_runs"] == extended["error_runs"] == extended["complete_evidence_missing_runs"] == _ZERO
        and extended["applied_runs"] + extended["omitted_ineligible_runs"] == extended["classified_runs"]
        and supplemental["vm_semantic"]["tests"] == _VM_TEST_COUNT
        and supplemental["vm_semantic"]["failures"] == supplemental["vm_semantic"]["errors"] == _ZERO
        and supplemental["composition"]["tests"] == _COMPOSITION_TEST_COUNT
        and supplemental["composition"]["failures"] == supplemental["composition"]["errors"] == _ZERO
        and supplemental["differential_fuzz"]["cases"] == _FUZZ_CASE_COUNT
        and supplemental["differential_fuzz"]["failures"] == _ZERO
    )


def test_published_differential_workflow_44213229027_keeps_unclosed_gates_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["supplemental_campaigns"]["cross_format"]
        == {
            "report_count": _CROSS_FORMAT_REPORT_COUNT,
            "tests": _CROSS_FORMAT_TEST_COUNT,
            "failures": _ZERO,
            "errors": _ZERO,
            "skipped": _CROSS_FORMAT_SKIPPED_COUNT,
        }
        and all(status == "open" for status in summary["release_criteria"].values())
        and all(
            readiness["criteria"][criterion]["status"] == "open"
            for criterion in (
                "all_named_adversarial_analyzers",
                "cross_platform_parity",
                "published_resistance_results",
            )
        )
    )
