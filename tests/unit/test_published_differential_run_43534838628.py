"""Regression checks for the November 14 differential campaign evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"
_REPORT_PATH = _DOCS / "protection-differential-run-2026-11-14-43534838628.json"
_RUN_ID = 43_534_838_628
_SOURCE_COMMIT = "72697b8b02e3fd6b7aac6f2ed1cca60d38d94971"
_ZERO = 0
_CORE_PASS_COUNT = 10
_CORE_CLASSIFIED_RUNS = 10_860
_CORE_APPLIED_RUNS = 3_565
_EXTENDED_PASS_COUNT = 12
_EXTENDED_CLASSIFIED_RUNS = 13_032
_EXTENDED_APPLIED_RUNS = 3_374
_COMPOSITION_CASES = 2_208
_COMPOSITION_PAIRS = 44
_PUBLIC_SAMPLE_COUNT = 360
_STATIC_RECOVERY_COUNT = 2_160
_PLATFORM_COUNT = 5
_PLATFORM_CASE_COUNT = 73
_VM_FIXTURE_COUNT = 1_005
_FUZZ_SHARD_COUNT = 48
_FUZZ_CASE_COUNT = 3_072
_FUZZ_TARGET_RUNS = 30_720
_ARCHIVE_COUNT = 8


def _report() -> dict[str, Any]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_differential_run_binds_success_to_source_commit() -> None:
    workflow = _report()["workflow"]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["status"] == "completed"
        and workflow["conclusion"] == "success"
        and workflow["jobs"] == {"total": 85, "successful": 85, "failed": _ZERO, "skipped": _ZERO}
        and workflow["current_main_runtime_source_unchanged_since_source_commit"] is True
    )


def test_differential_run_records_zero_core_and_extended_failures() -> None:
    results = _report()["results"]
    core = results["core"]
    extended = results["extended"]

    expect(
        core["pass_count"] == _CORE_PASS_COUNT
        and core["total_classified_runs"] == _CORE_CLASSIFIED_RUNS
        and core["total_applied_runs"] == _CORE_APPLIED_RUNS
        and core["total_error_runs"] == core["total_failed_seed_runs"] == _ZERO
        and extended["pass_count"] == _EXTENDED_PASS_COUNT
        and extended["total_classified_runs"] == _EXTENDED_CLASSIFIED_RUNS
        and extended["total_applied_runs"] == _EXTENDED_APPLIED_RUNS
        and extended["total_error_runs"] == extended["total_failed_seed_runs"] == _ZERO
    )


def test_differential_run_preserves_public_and_composition_limits() -> None:
    results = _report()["results"]

    expect(
        results["composition"]
        == {"cases": _COMPOSITION_CASES, "directional_pairs": _COMPOSITION_PAIRS, "errors": _ZERO, "failures": _ZERO}
        and results["public_compatibility"]["samples"] == _PUBLIC_SAMPLE_COUNT
        and results["public_compatibility"]["failed_samples"] == _ZERO
        and results["public_compatibility"]["static_recovery_samples"] == _STATIC_RECOVERY_COUNT
        and results["public_compatibility"]["static_recovery_analyzer"] == "radare2"
        and results["public_compatibility"]["decompiler_analyzers_omitted"] == ["binary_ninja", "ghidra", "ida_pro"]
    )


def test_differential_run_records_platform_previews_without_parity_claim() -> None:
    preview = _report()["results"]["platform_previews"]

    expect(
        preview["platform_count"] == _PLATFORM_COUNT
        and preview["case_count"] == _PLATFORM_CASE_COUNT
        and preview["failures"] == preview["errors"] == preview["skips"] == _ZERO
        and preview["platforms"]
        == {"elf-arm-32": 6, "elf-arm64": 7, "elf-x86-32": 8, "macos-arm64": 35, "windows-pe": 17}
        and _report()["readiness"]["cross_platform_parity"] == "open"
    )


def test_differential_run_records_vm_parity_and_fuzz_campaigns() -> None:
    results = _report()["results"]
    vm = results["vm_semantics"]
    fuzz = results["fuzz"]

    expect(
        vm["fixtures"] == vm["passed"] == vm["qemu_completed_pairs"] == _VM_FIXTURE_COUNT
        and vm["failed"] == vm["qemu_divergent_pairs"] == vm["qemu_missing_pairs"] == _ZERO
        and fuzz["shards"] == _FUZZ_SHARD_COUNT
        and fuzz["cases"] == _FUZZ_CASE_COUNT
        and fuzz["total_target_runs"] == _FUZZ_TARGET_RUNS
        and set(fuzz["target_runs"].values()) == {_FUZZ_CASE_COUNT}
        and fuzz["failures"] == _ZERO
    )


def test_differential_run_hashes_all_archived_source_reports() -> None:
    archives = _report()["archives"]

    expect(
        len(archives) == _ARCHIVE_COUNT
        and all(
            hashlib.sha256((_ROOT / item["path"]).read_bytes()).hexdigest() == item["sha256"]
            and hashlib.sha256(gzip.decompress((_ROOT / item["path"]).read_bytes())).hexdigest()
            == item["uncompressed_sha256"]
            and len(gzip.decompress((_ROOT / item["path"]).read_bytes())) == item["uncompressed_size_bytes"]
            for item in archives.values()
        )
    )


def test_differential_run_retains_open_release_blockers() -> None:
    readiness = json.loads((_DOCS / "one-zero-readiness.json").read_text(encoding="utf-8"))
    criteria = readiness["criteria"]

    expect(
        criteria["published_correctness_results"]["status"] == "complete"
        and criteria["published_cost_results"]["status"] == "complete"
        and criteria["cross_platform_parity"]["status"] == "open"
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and f"docs/{_REPORT_PATH.name}" in criteria["published_correctness_results"]["evidence"]
        and f"docs/{_REPORT_PATH.name}" in criteria["published_cost_results"]["evidence"]
        and f"docs/{_REPORT_PATH.name}" in criteria["cross_platform_parity"]["evidence"]
    )
