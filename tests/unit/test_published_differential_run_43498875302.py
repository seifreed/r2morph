"""Regression checks for the November 13 full differential campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"
_REPORT_PATH = _DOCS / "protection-differential-run-2026-11-13-43498875302.json"
_READINESS_PATH = _DOCS / "one-zero-readiness.json"
_RUN_ID = 43_498_875_302
_COMMIT = "b012cd0adcc09c4d8dca0b7035bd6be7e09ab82a"
_ZERO = 0
_ONE_HUNDRED_PERCENT = 100.0
_SHA256_LENGTH = 64
_SUCCESSFUL_JOBS = 85
_CORE_PASS_COUNT = 10
_CORE_RUN_COUNT = 10_860
_CORE_APPLIED_RUNS = 3_565
_EXTENDED_PASS_COUNT = 12
_EXTENDED_RUN_COUNT = 13_032
_EXTENDED_APPLIED_RUNS = 3_374
_PLATFORM_PREVIEW_COUNT = 5
_PLATFORM_CASE_COUNT = 73
_PUBLIC_SAMPLE_COUNT = 360
_STATIC_RECOVERY_MEASUREMENTS = 2_160
_VM_FIXTURE_COUNT = 1_005
_MATURITY_DECOMPILER_BLOCKERS = 22
_MATURITY_COMPOSITION_CASES = 2_208
_PUBLIC_SHARD_COUNT = 4
_SOURCE_ARTIFACT_GROUP_COUNT = 4


def _report() -> dict[str, Any]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_differential_campaign_binds_success_to_source_commit() -> None:
    report = _report()

    expect(
        report["workflow_run"] == _RUN_ID
        and report["commit"] == _COMMIT
        and report["workflow_jobs"] == {"completed": _SUCCESSFUL_JOBS, "successful": _SUCCESSFUL_JOBS, "failed": _ZERO}
    )


def test_differential_campaign_records_all_seed_results() -> None:
    differential = _report()["differential"]

    expect(
        differential["core_pass_count"] == _CORE_PASS_COUNT
        and differential["core_classified_runs"] == _CORE_RUN_COUNT
        and differential["core_applied_runs"] == _CORE_APPLIED_RUNS
        and differential["core_error_runs"] == differential["core_failed_seed_runs"] == _ZERO
        and differential["core_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
        and differential["extended_pass_count"] == _EXTENDED_PASS_COUNT
        and differential["extended_classified_runs"] == _EXTENDED_RUN_COUNT
        and differential["extended_applied_runs"] == _EXTENDED_APPLIED_RUNS
        and differential["extended_error_runs"] == differential["extended_failed_seed_runs"] == _ZERO
        and differential["extended_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
    )


def test_differential_campaign_retains_maturity_blockers() -> None:
    differential = _report()["differential"]

    expect(
        differential["maturity_decompiler_blockers"] == _MATURITY_DECOMPILER_BLOCKERS
        and differential["maturity_composition_cases"] == _MATURITY_COMPOSITION_CASES
        and differential["maturity_composition_failures"] == differential["maturity_composition_errors"] == _ZERO
    )


def test_differential_campaign_records_bounded_platform_previews() -> None:
    preview = _report()["platform_preview"]
    aggregate = json.loads((_DOCS / preview["summary_report"]).read_text(encoding="utf-8"))
    observed = {}

    for name, row in preview["platform_reports"].items():
        root = ElementTree.parse(_DOCS / row["file"]).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        observed[name] = {
            "tests": sum(int(suite.attrib.get("tests", "0")) for suite in suites),
            "failures": sum(int(suite.attrib.get("failures", "0")) for suite in suites),
            "errors": sum(int(suite.attrib.get("errors", "0")) for suite in suites),
            "skipped": sum(int(suite.attrib.get("skipped", "0")) for suite in suites),
        }

    expect(
        preview["status"] == aggregate["summary"]["status"] == "complete"
        and preview["platform_count"] == preview["complete_platforms"] == _PLATFORM_PREVIEW_COUNT
        and preview["case_count"] == _PLATFORM_CASE_COUNT
        and preview["failure_count"] == preview["error_count"] == preview["skipped_count"] == _ZERO
        and preview["parity_claim"] is False
        and set(observed) == set(aggregate["platforms"])
        and all(
            observed[name]["tests"] == row["case_count"]
            and observed[name]["failures"] == row["failure_count"] == _ZERO
            and observed[name]["errors"] == row["error_count"] == _ZERO
            and observed[name]["skipped"] == _ZERO
            and row["missing_required_cases"] == []
            for name, row in aggregate["platforms"].items()
        )
    )


def test_differential_campaign_records_public_corpus_and_static_recovery() -> None:
    public = _report()["public_compatibility"]
    aggregate = json.loads((_DOCS / public["report"]).read_text(encoding="utf-8"))

    expect(
        public["status"] == aggregate["status"] == "passed"
        and public["sample_count"] == aggregate["sample_count"] == _PUBLIC_SAMPLE_COUNT
        and public["shard_count"] == aggregate["shards"] == _PUBLIC_SHARD_COUNT
        and public["static_recovery_measurements"] == _STATIC_RECOVERY_MEASUREMENTS
        and public["differential_failed_samples"] == aggregate["differential_failed_samples"] == _ZERO
        and public["static_recovery_failed_samples"] == aggregate["static_recovery_failed_samples"] == _ZERO
    )


def test_differential_campaign_records_vm_semantic_oracle_results() -> None:
    semantic = _report()["vm_semantic"]
    campaign = json.loads((_DOCS / "protection-vm-semantic-2026-11-13-43498875302.json").read_text(encoding="utf-8"))

    expect(
        semantic["status"] == campaign["status"] == "passed"
        and semantic["fixture_count"] == semantic["passed_count"] == campaign["fixture_count"] == _VM_FIXTURE_COUNT
        and semantic["failed_count"] == campaign["failed_count"] == _ZERO
        and semantic["qemu_completed_pairs"] == campaign["qemu_summary"]["completed_pairs"] == _VM_FIXTURE_COUNT
        and semantic["qemu_divergent_pairs"] == campaign["qemu_summary"]["divergent_pairs"] == _ZERO
        and semantic["qemu_missing_pairs"] == campaign["qemu_summary"]["missing_pairs"] == _ZERO
        and semantic["qemu_unavailable_pairs"] == campaign["qemu_summary"]["unavailable_pairs"] == _ZERO
    )


def test_differential_campaign_binds_artifact_and_retained_report_hashes() -> None:
    groups = _report()["source_artifacts"]
    retained = [row for group in groups for row in group["files"] if "retained_as" in row]

    expect(
        len(groups) == _SOURCE_ARTIFACT_GROUP_COUNT
        and all(len(row["sha256"]) == _SHA256_LENGTH for group in groups for row in group["files"])
        and all(
            hashlib.sha256((_DOCS / row["retained_as"]).read_bytes()).hexdigest() == row["sha256"] for row in retained
        )
    )


def test_differential_campaign_updates_evidence_without_claiming_parity() -> None:
    readiness = json.loads(_READINESS_PATH.read_text(encoding="utf-8"))
    path = f"docs/{_REPORT_PATH.name}"

    expect(
        all(
            path in readiness["criteria"][criterion]["evidence"]
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


def test_differential_campaign_reports_no_host_paths() -> None:
    manifest = _REPORT_PATH.read_text(encoding="utf-8")
    retained_paths = [
        _DOCS / _report()["platform_preview"]["summary_report"],
        _DOCS / _report()["public_compatibility"]["report"],
        _DOCS / "protection-vm-semantic-2026-11-13-43498875302.json",
        *(_DOCS / row["file"] for row in _report()["platform_preview"]["platform_reports"].values()),
    ]
    serialized = manifest + "".join(path.read_text(encoding="utf-8") for path in retained_paths)

    expect(not any(prefix in serialized for prefix in ("/Users/", "/Applications/", "/private/", "/home/")))
