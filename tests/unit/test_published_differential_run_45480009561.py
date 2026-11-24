"""Verify the completed current-source differential campaign manifest."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/differential-run-2026-11-24-45480009561.json"
_PUBLIC_REPORT = _ROOT / "docs/public-compatibility-aggregate-45480009561.json"
_PLATFORM_REPORT = _ROOT / "docs/protection-platform-preview-2026-11-24-45480009561.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "a4f4dcba12020cda4fa7717c4361c027d4b09081"
_RUN_ID = 45480009561
_ATTEMPT = 1
_AGGREGATE_ARTIFACT_ID = 14963154263
_CORE_PASS_COUNT = 10
_CORE_RUNS = 10860
_CORE_APPLIED = 3480
_CORE_OMITTED = 7380
_EXTENDED_PASS_COUNT = 12
_EXTENDED_RUNS = 13032
_EXTENDED_APPLIED = 3406
_EXTENDED_OMITTED = 9626
_PUBLIC_SAMPLE_COUNT = 370
_PLATFORM_CASE_COUNT = 78
_VM_CASE_COUNT = 1005
_DECOMPILER_BLOCKERS = 22
_STATIC_RECOVERY_MEASUREMENTS = 2220
_VM_SEEDS = [20260916, 20260917, 20260918]


def test_current_differential_manifest_binds_successful_run_and_source() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["run_id"] == _RUN_ID
        and report["run_attempt"] == _ATTEMPT
        and report["source_commit"] == _SOURCE_COMMIT
        and report["conclusion"] == "success"
        and report["jobs"] == {"total": 86, "passed": 86, "failed": 0, "cancelled": 0}
        and report["aggregate_artifact"]["id"] == _AGGREGATE_ARTIFACT_ID
        and report["aggregate_artifact"]["name"] == "differential-corpus-merged-45480009561-1"
        and all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in report["aggregate_artifact"]["reports"].values())
    )


def test_differential_totals_preserve_scope_and_classification() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    core = report["core_differential"]
    extended = report["extended_differential"]
    composition = report["composition"]

    expect(
        core["scope"] == extended["scope"] == "Linux ELF x86-64"
        and core["pass_count"] == _CORE_PASS_COUNT
        and core["classified_seed_runs"] == core["complete_evidence_runs"] == _CORE_RUNS
        and core["applied_runs"] == _CORE_APPLIED
        and core["omitted_runs"] == _CORE_OMITTED
        and core["failed_seed_runs"] == core["error_runs"] == core["semantic_failures"] == 0
        and extended["pass_count"] == _EXTENDED_PASS_COUNT
        and extended["classified_seed_runs"] == extended["complete_evidence_runs"] == _EXTENDED_RUNS
        and extended["applied_runs"] == _EXTENDED_APPLIED
        and extended["omitted_runs"] == _EXTENDED_OMITTED
        and extended["failed_seed_runs"] == extended["error_runs"] == extended["semantic_failures"] == 0
        and composition == {"directional_pair_count": 44, "case_count": 2208, "failed_cases": 0, "error_cases": 0}
    )


def test_current_aggregates_match_published_reports_and_keep_gates_honest() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    public = json.loads(_PUBLIC_REPORT.read_text(encoding="utf-8"))
    platform = json.loads(_PLATFORM_REPORT.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    public_result = report["public_compatibility"]
    vm = report["vm_semantic"]

    expect(
        hashlib.sha256(_PUBLIC_REPORT.read_bytes()).hexdigest() == public_result["artifact"]["report_sha256"]
        and public["status"] == public_result["status"] == "passed"
        and public["sample_count"] == public_result["sample_count"] == _PUBLIC_SAMPLE_COUNT
        and public["differential_failed_samples"] == public_result["differential_failed_samples"] == 0
        and public["static_recovery_failed_samples"] == public_result["static_recovery_failed_samples"] == 0
        and public_result["static_recovery_measurements"] == _STATIC_RECOVERY_MEASUREMENTS
        and public["passes"] == public_result["passes"]
        and platform["summary"]["case_count"] == platform["summary"]["passed_case_count"] == _PLATFORM_CASE_COUNT
        and platform["summary"]["failed_case_count"] == platform["summary"]["error_case_count"] == 0
        and platform["summary"]["skipped_case_count"] == 0
        and hashlib.sha256(_PLATFORM_REPORT.read_bytes()).hexdigest() == report["platform_preview"]["report_sha256"]
        and vm["fixture_seed_cases"] == vm["passed_cases"] == vm["qemu_oracle_pairs"] == _VM_CASE_COUNT
        and vm["seeds"] == _VM_SEEDS
        and vm["failed_cases"]
        == vm["qemu_divergent_pairs"]
        == vm["qemu_missing_pairs"]
        == vm["qemu_unavailable_pairs"]
        == 0
        and report["maturity_evidence"]["decompiler_blockers"] == _DECOMPILER_BLOCKERS
        and report["maturity_evidence"]["composition_blockers"] == 0
        and readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in readiness["criteria"]["published_correctness_results"]["evidence"]
        and Path(__file__).relative_to(_ROOT).as_posix()
        in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _PUBLIC_REPORT.relative_to(_ROOT).as_posix()
        in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _REPORT.relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
        and Path(__file__).relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
    )
