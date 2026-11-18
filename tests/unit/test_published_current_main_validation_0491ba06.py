"""Pin current-main cross-platform, differential, and adversarial evidence."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = "docs/current-main-validation-2026-11-18-0491ba06.json"
_READINESS_PATH = "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "0491ba06a09240eee7b36241cc4d8e4b040a7a83"
_CI_RUN_ID = 44258279805
_DIFFERENTIAL_RUN_ID = 44258279838
_FUZZ_RUN_ID = 44258279826
_ADVERSARIAL_RUN_ID = 44280768566
_CORE_CLASSIFICATIONS = 10_860
_EXTENDED_CLASSIFICATIONS = 13_032
_FUZZ_TARGET_RUNS = 50_000
_TOTAL_FUZZ_TARGET_RUNS = 150_000
_ADVERSARIAL_FIXTURES = 362
_GENERATED_FIXTURES = 200
_ADVERSARIAL_PASSES = 22
_COMPLETED_ANALYZER_RUNS = 55_220
_EXPECTED_ANALYZER_RUNS = 71_676
_BINARY_NINJA_UNAVAILABLE_RUNS = 7_964
_UNSUPPORTED_VIRTUALIZATION_FUNCTIONS = 14
_DIFFERENTIAL_JOBS = 85
_SUCCESSFUL_CI_JOBS = 11
_CANCELLED_CI_JOBS = 4
_AUTOMATED_REVIEW_CHECKS = 28


def _manifest() -> dict[str, object]:
    return json.loads((_ROOT / _MANIFEST_PATH).read_text(encoding="utf-8"))


def test_current_main_validation_manifest_binds_source_commit_and_runs() -> None:
    manifest = _manifest()

    expect(
        manifest["source_commit"] == _SOURCE_COMMIT
        and manifest["ci"]["run_id"] == _CI_RUN_ID
        and manifest["differential"]["run_id"] == _DIFFERENTIAL_RUN_ID
        and manifest["continuous_fuzz"]["run_id"] == _FUZZ_RUN_ID
        and manifest["adversarial"]["run_id"] == _ADVERSARIAL_RUN_ID
    )


def test_current_main_differential_evidence_records_complete_bounded_runs() -> None:
    differential = _manifest()["differential"]
    core = differential["core"]
    extended = differential["extended"]

    expect(
        differential["conclusion"] == "success"
        and differential["jobs"] == _DIFFERENTIAL_JOBS
        and core["classified_runs"] == core["complete_evidence_runs"] == _CORE_CLASSIFICATIONS
        and core["failed_runs"] == core["error_runs"] == core["missing_evidence_runs"] == 0
        and extended["classified_runs"] == extended["complete_evidence_runs"] == _EXTENDED_CLASSIFICATIONS
        and extended["failed_runs"] == extended["error_runs"] == extended["missing_evidence_runs"] == 0
    )


def test_current_main_fuzz_evidence_covers_all_platforms_without_failures() -> None:
    fuzz = _manifest()["continuous_fuzz"]

    expect(
        fuzz["conclusion"] == "success"
        and set(fuzz["platforms"]) == {"ubuntu", "windows", "macos"}
        and fuzz["total_target_runs"] == _TOTAL_FUZZ_TARGET_RUNS
        and fuzz["total_failures"] == 0
        and all(
            report["target_runs"] == _FUZZ_TARGET_RUNS and report["failure_count"] == 0
            for report in fuzz["platforms"].values()
        )
    )


def test_current_main_adversarial_evidence_keeps_analyzer_gaps_explicit() -> None:
    adversarial = _manifest()["adversarial"]

    expect(
        adversarial["fixtures"] == _ADVERSARIAL_FIXTURES
        and adversarial["generated_fixtures"] == _GENERATED_FIXTURES
        and adversarial["pass_count"] == _ADVERSARIAL_PASSES
        and adversarial["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUNS
        and adversarial["expected_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and adversarial["unavailable_by_tool"]["binary-ninja"] == _BINARY_NINJA_UNAVAILABLE_RUNS
        and adversarial["unsupported_virtualization_functions"] == _UNSUPPORTED_VIRTUALIZATION_FUNCTIONS
        and adversarial["error_analyzer_runs"] == 0
    )


def test_current_main_ci_and_automated_review_do_not_claim_full_signoff() -> None:
    manifest = _manifest()
    ci = manifest["ci"]
    review = manifest["automated_review"]

    expect(
        ci["conclusion"] == "cancelled"
        and ci["successful_jobs"] == _SUCCESSFUL_CI_JOBS
        and len(ci["cancelled_jobs"]) == _CANCELLED_CI_JOBS
        and review["conclusion"] == "success"
        and review["passed_checks"] == _AUTOMATED_REVIEW_CHECKS
        and review["human_signoff"] == "not-attested"
        and review["release_decision"] == "block-vm-milestone"
    )


def test_current_main_readiness_keeps_three_release_gates_open() -> None:
    readiness = json.loads((_ROOT / _READINESS_PATH).read_text(encoding="utf-8"))

    expect(
        readiness["status"] == "blocked"
        and set(readiness["blocking_criteria"])
        == {"all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"}
        and all(readiness["criteria"][key]["status"] == "open" for key in readiness["blocking_criteria"])
    )
