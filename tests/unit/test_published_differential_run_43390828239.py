"""Regression checks for the pinned November 13 differential campaign."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-differential-run-2026-11-13-43390828239.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_RUN_ID = 43_390_828_239
_COMMIT = "acfc0995825d2fe5fdbcd56d7763508a4512f596"
_ZERO = 0
_ONE_HUNDRED_PERCENT = 100.0
_SHA256_LENGTH = 64
_CORE_PASS_COUNT = 10
_CORE_RUN_COUNT = 10_860
_CORE_APPLIED_RUNS = 3_565
_CORE_OMITTED_RUNS = 7_295
_EXTENDED_PASS_COUNT = 12
_EXTENDED_RUN_COUNT = 13_032
_EXTENDED_APPLIED_RUNS = 3_374
_EXTENDED_OMITTED_RUNS = 9_658
_PLATFORM_PREVIEW_COUNT = 5
_PLATFORM_CASE_COUNT = 73
_COMPOSITION_CASE_COUNT = 2_208
_DECOMPILER_BLOCKER_COUNT = 22
_PUBLIC_SAMPLE_COUNT = 360
_PUBLIC_SHARD_COUNT = 4
_STATIC_RECOVERY_MEASUREMENTS = 2_160
_VM_FIXTURE_COUNT = 1_005
_SOURCE_ARTIFACT_COUNT = 4
_SOURCE_ARTIFACT_HASHES = {
    14_026_235_210: "4143f7b769f33e427e353243c233ddb63b248be33deef813d9e5c4eebb0a7f77",
    14_023_165_793: "7482c52e0861009232653c1ecea46c77c69eccafb43dc27245938010091eb0ff",
    14_024_344_240: "10a2e1593357b9e40e111865df24877bd0eea457e190b10775c623660266d621",
    14_023_241_281: "55f08d348f1c299afc4fce1a0f2692bd5ddd36d660f93e2d9f2c00f8316ba702",
}


def _report() -> dict[str, Any]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_differential_run_binds_successful_jobs_to_source_commit() -> None:
    report = _report()

    expect(
        report["workflow_run"] == _RUN_ID
        and report["commit"] == _COMMIT
        and report["workflow_jobs"] == {"completed": 85, "successful": 85, "failed": _ZERO}
    )


def test_differential_run_records_zero_failures_and_complete_evidence() -> None:
    differential = _report()["differential"]

    expect(
        differential["core_pass_count"] == _CORE_PASS_COUNT
        and differential["core_classified_runs"] == _CORE_RUN_COUNT
        and differential["core_applied_runs"] == _CORE_APPLIED_RUNS
        and differential["core_omitted_runs"] == _CORE_OMITTED_RUNS
        and differential["core_error_runs"] == differential["core_failed_seed_runs"] == _ZERO
        and differential["core_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
        and differential["extended_pass_count"] == _EXTENDED_PASS_COUNT
        and differential["extended_classified_runs"] == _EXTENDED_RUN_COUNT
        and differential["extended_applied_runs"] == _EXTENDED_APPLIED_RUNS
        and differential["extended_omitted_runs"] == _EXTENDED_OMITTED_RUNS
        and differential["extended_error_runs"] == differential["extended_failed_seed_runs"] == _ZERO
        and differential["extended_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
    )


def test_differential_run_keeps_preview_and_resistance_limits_explicit() -> None:
    report = _report()

    expect(
        report["platform_preview"]["case_count"] == _PLATFORM_CASE_COUNT
        and report["platform_preview"]["platform_count"]
        == report["platform_preview"]["complete_platforms"]
        == _PLATFORM_PREVIEW_COUNT
        and report["platform_preview"]["failure_count"]
        == report["platform_preview"]["error_count"]
        == report["platform_preview"]["skipped_count"]
        == _ZERO
        and report["platform_preview"]["parity_claim"] is False
        and report["differential"]["maturity_decompiler_blockers"] == _DECOMPILER_BLOCKER_COUNT
        and report["differential"]["maturity_composition_cases"] == _COMPOSITION_CASE_COUNT
        and report["differential"]["maturity_composition_failures"] == _ZERO
    )


def test_differential_run_records_public_and_vm_results() -> None:
    report = _report()

    expect(
        report["public_compatibility"]["status"] == "passed"
        and report["public_compatibility"]["sample_count"] == _PUBLIC_SAMPLE_COUNT
        and report["public_compatibility"]["shard_count"] == _PUBLIC_SHARD_COUNT
        and report["public_compatibility"]["static_recovery_measurements"] == _STATIC_RECOVERY_MEASUREMENTS
        and report["public_compatibility"]["differential_failed_samples"]
        == report["public_compatibility"]["static_recovery_failed_samples"]
        == _ZERO
        and report["vm_semantic"]["status"] == "passed"
        and report["vm_semantic"]["fixture_count"]
        == report["vm_semantic"]["passed_count"]
        == report["vm_semantic"]["qemu_completed_pairs"]
        == _VM_FIXTURE_COUNT
        and report["vm_semantic"]["failed_count"]
        == report["vm_semantic"]["qemu_divergent_pairs"]
        == report["vm_semantic"]["qemu_missing_pairs"]
        == report["vm_semantic"]["qemu_unavailable_pairs"]
        == _ZERO
    )


def test_differential_run_binds_all_retained_source_artifact_hashes() -> None:
    sources = _report()["source_artifacts"]

    expect(
        len(sources) == _SOURCE_ARTIFACT_COUNT
        and {source["artifact_id"]: source["artifact_sha256"] for source in sources} == _SOURCE_ARTIFACT_HASHES
        and all(
            len(source["artifact_sha256"]) == _SHA256_LENGTH
            and all(len(file["sha256"]) == _SHA256_LENGTH for file in source["files"])
            for source in sources
        )
    )


def test_differential_run_is_linked_without_closing_open_release_gates() -> None:
    readiness = json.loads(_READINESS_PATH.read_text(encoding="utf-8"))
    report_path = f"docs/{_REPORT_PATH.name}"

    expect(
        all(
            report_path in readiness["criteria"][criterion]["evidence"]
            for criterion in (
                "cross_platform_parity",
                "published_cost_results",
                "published_correctness_results",
            )
        )
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_cost_results"]["status"] == "complete"
        and readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and readiness["status"] == "blocked"
    )


def test_differential_run_contains_no_analyst_host_paths() -> None:
    serialized = _REPORT_PATH.read_text(encoding="utf-8")

    expect(not any(path in serialized for path in ("/Users/", "/Applications/", "/private/", "/home/")))
