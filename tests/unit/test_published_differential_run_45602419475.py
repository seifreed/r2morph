"""Verify source-bound differential and bounded platform evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "docs/differential-run-2026-11-25-45602419475.json"
_PLATFORM = _ROOT / "docs/platform-evidence-45602419475.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_differential_run_45602419475.py"
_RUN_ID = 45602419475
_SOURCE_COMMIT = "9c9177952decf745674715563fbfa8e73a92a090"
_CORE_RUNS, _CORE_APPLIED, _CORE_OMITTED = 10860, 3480, 7380
_EXTENDED_RUNS, _EXTENDED_APPLIED, _EXTENDED_OMITTED = 13032, 3406, 9626
_PUBLIC_SAMPLES, _STATIC_RECOVERY_SAMPLES = 370, 2220
_VM_CASES, _PLATFORM_CASES, _DECOMPILER_BLOCKERS = 1005, 78, 22


def _report(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    item = cast(dict[str, Any], manifest[key])
    relative = cast(str, item["report"])
    path = _ROOT / relative
    compressed = path.read_bytes()
    expect(hashlib.sha256(compressed).hexdigest() == item["report_sha256"])
    return json.loads(gzip.decompress(compressed))


def test_manifest_binds_successful_source_and_differential_reports() -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    core = _report(manifest, "core_differential")
    extended = _report(manifest, "extended_differential")
    maturity = _report(manifest, "maturity_evidence")

    expect(
        manifest["run_id"] == _RUN_ID
        and manifest["run_attempt"] == 1
        and manifest["source_commit"] == _SOURCE_COMMIT
        and manifest["conclusion"] == "success"
        and manifest["jobs"] == {"total": 86, "passed": 86, "failed": 0, "cancelled": 0}
        and core["campaign_summary"]["total_classified_runs"] == _CORE_RUNS
        and core["campaign_summary"]["total_applied_runs"] == _CORE_APPLIED
        and core["campaign_summary"]["total_omitted_runs"] == _CORE_OMITTED
        and core["campaign_summary"]["total_error_runs"] == 0
        and core["campaign_summary"]["total_failed_seed_runs"] == 0
        and core["campaign_summary"]["semantic_failure_percent"] == 0.0
        and extended["campaign_summary"]["total_classified_runs"] == _EXTENDED_RUNS
        and extended["campaign_summary"]["total_applied_runs"] == _EXTENDED_APPLIED
        and extended["campaign_summary"]["total_omitted_runs"] == _EXTENDED_OMITTED
        and extended["campaign_summary"]["total_error_runs"] == 0
        and extended["campaign_summary"]["total_failed_seed_runs"] == 0
        and maturity["summary"]["blocker_totals"]["decompiler"] == _DECOMPILER_BLOCKERS
        and manifest["composition"]
        == {"directional_pair_count": 44, "case_count": 2208, "failed_cases": 0, "error_cases": 0}
    )


def test_compatibility_vm_and_bounded_platform_results_keep_limits_explicit() -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    public = _report(manifest, "public_compatibility")
    vm = _report(manifest, "vm_semantic")
    platform_bytes = _PLATFORM.read_bytes()
    platform = json.loads(platform_bytes)
    public_result = manifest["public_compatibility"]
    platform_result = manifest["platform_preview"]
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))

    expect(
        public["matrix"]["built_samples"] == public["matrix"]["passed_samples"] == _PUBLIC_SAMPLES
        and public["matrix"]["failed_samples"] == 0
        and public["static_recovery"]["measured_samples"] == _STATIC_RECOVERY_SAMPLES
        and public["static_recovery"]["failed_samples"] == 0
        and public_result["differential_failed_samples"] == 0
        and vm["status"] == "passed"
        and vm["passed_count"] == vm["qemu_summary"]["completed_pairs"] == _VM_CASES
        and vm["qemu_summary"]["divergent_pairs"] == vm["qemu_summary"]["missing_pairs"] == 0
        and hashlib.sha256(platform_bytes).hexdigest() == platform_result["report_sha256"]
        and platform["summary"]
        == {"complete_platforms": 6, "incomplete_platforms": [], "platform_count": 6, "status": "complete"}
        and platform_result["case_count"] == platform_result["passed_cases"] == _PLATFORM_CASES
        and platform_result["failed_cases"] == platform_result["error_cases"] == platform_result["skipped_cases"] == 0
        and sum(item["case_count"] for item in platform["platforms"].values()) == _PLATFORM_CASES
        and all(
            item["failure_count"] == item["error_count"] == item["skipped_count"] == 0
            for item in platform["platforms"].values()
        )
        and readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _MANIFEST.relative_to(_ROOT).as_posix()
        in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _PLATFORM.relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["cross_platform_parity"]["evidence"]
    )
