"""Verify the source-bound differential campaign and bounded platform evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from defusedxml import ElementTree as DefusedElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/differential-run-2026-11-25-45544822953.json"
_PLATFORM = _ROOT / "docs/protection-platform-preview-2026-11-25-45544822953.json"
_PLATFORM_XML = _ROOT / "docs/protection-platform-preview-2026-11-25-45544822953"
_PUBLIC = _ROOT / "docs/public-compatibility-aggregate-45480009561.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_differential_run_45544822953.py"
_RUN_ID = 45544822953
_ATTEMPT = 1
_SOURCE_COMMIT = "1dabf440aa7b2a9443a67c692fa14c03d24c9fe5"
_CORE_RUNS = 10860
_CORE_APPLIED = 3480
_CORE_OMITTED = 7380
_EXTENDED_RUNS = 13032
_EXTENDED_APPLIED = 3406
_EXTENDED_OMITTED = 9626
_COMPOSITION_CASES = 2208
_PUBLIC_SAMPLES = 370
_STATIC_RECOVERY_MEASUREMENTS = 2220
_VM_CASES = 1005
_DECOMPILER_BLOCKERS = 22
_PLATFORM_CASES = {
    "elf-arm-32": 6,
    "elf-arm64": 7,
    "elf-x86-32": 8,
    "macos-arm64": 36,
    "macos-x86-64": 3,
    "windows-pe": 18,
}


def _xml_counts(path: Path) -> tuple[int, int, int, int]:
    root = DefusedElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    return tuple(
        sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")
    )


def test_run_manifest_binds_successful_campaign_and_complete_classification() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    core = report["core_differential"]
    extended = report["extended_differential"]

    expect(
        report["run_id"] == _RUN_ID
        and report["run_attempt"] == _ATTEMPT
        and report["source_commit"] == _SOURCE_COMMIT
        and report["conclusion"] == "success"
        and report["jobs"] == {"total": 86, "passed": 86, "failed": 0, "cancelled": 0}
        and core["scope"] == extended["scope"] == "Linux ELF x86-64"
        and core["classified_seed_runs"] == core["complete_evidence_runs"] == _CORE_RUNS
        and core["applied_runs"] == _CORE_APPLIED
        and core["omitted_runs"] == _CORE_OMITTED
        and core["failed_seed_runs"] == core["error_runs"] == core["semantic_failures"] == 0
        and extended["classified_seed_runs"] == extended["complete_evidence_runs"] == _EXTENDED_RUNS
        and extended["applied_runs"] == _EXTENDED_APPLIED
        and extended["omitted_runs"] == _EXTENDED_OMITTED
        and extended["failed_seed_runs"] == extended["error_runs"] == extended["semantic_failures"] == 0
        and report["composition"]
        == {
            "directional_pair_count": 44,
            "case_count": _COMPOSITION_CASES,
            "failed_cases": 0,
            "error_cases": 0,
        }
        and all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in report["aggregate_artifact"]["reports"].values())
        and re.fullmatch(r"[0-9a-f]{64}", report["aggregate_artifact"]["zip_sha256"])
    )


def test_platform_reports_are_hash_bound_and_have_no_failed_or_skipped_cases() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    platform = json.loads(_PLATFORM.read_text(encoding="utf-8"))
    preview = report["platform_preview"]
    aggregate = platform["summary"]

    expect(
        hashlib.sha256(_PLATFORM.read_bytes()).hexdigest() == preview["report_sha256"]
        and aggregate
        == {
            "complete_platforms": 6,
            "incomplete_platforms": [],
            "platform_count": 6,
            "status": "complete",
        }
        and preview["case_count"] == preview["passed_cases"] == sum(_PLATFORM_CASES.values())
        and preview["failed_cases"] == preview["error_cases"] == preview["skipped_cases"] == 0
        and set(platform["platforms"]) == set(_PLATFORM_CASES)
        and all(
            platform["platforms"][name]["case_count"] == count
            and platform["platforms"][name]["status"] == "complete"
            and platform["platforms"][name]["failure_count"]
            == platform["platforms"][name]["error_count"]
            == platform["platforms"][name]["skipped_count"]
            == 0
            and _xml_counts(_PLATFORM_XML / platform["platforms"][name]["report"]) == (count, 0, 0, 0)
            and hashlib.sha256((_PLATFORM_XML / platform["platforms"][name]["report"]).read_bytes()).hexdigest()
            == preview["junit_reports"][platform["platforms"][name]["report"]]
            for name, count in _PLATFORM_CASES.items()
        )
        and sum(_PLATFORM_CASES.values()) == preview["case_count"]
    )


def test_compatibility_vm_scope_and_readiness_remain_honest() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    public = json.loads(_PUBLIC.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    public_result = report["public_compatibility"]
    vm = report["vm_semantic"]

    expect(
        hashlib.sha256(_PUBLIC.read_bytes()).hexdigest() == public_result["artifact"]["report_sha256"]
        and public["status"] == public_result["status"] == "passed"
        and public["sample_count"] == public_result["sample_count"] == _PUBLIC_SAMPLES
        and public["differential_failed_samples"] == public["static_recovery_failed_samples"] == 0
        and public_result["static_recovery_measurements"] == _STATIC_RECOVERY_MEASUREMENTS
        and vm["fixture_seed_cases"] == vm["passed_cases"] == vm["qemu_oracle_pairs"] == _VM_CASES
        and vm["failed_cases"]
        == vm["qemu_divergent_pairs"]
        == vm["qemu_missing_pairs"]
        == vm["qemu_unavailable_pairs"]
        == 0
        and vm["seeds"] == [20260916, 20260917, 20260918]
        and report["maturity_evidence"]["decompiler_blockers"] == _DECOMPILER_BLOCKERS
        and readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["published_correctness_results"]["evidence"]
        and _PLATFORM.relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["cross_platform_parity"]["evidence"]
    )
