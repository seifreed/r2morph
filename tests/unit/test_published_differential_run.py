"""Regression checks for the pinned cross-platform differential campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-differential-run-2026-11-12-43165336266.json"
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_RUN_ID = 43_165_336_266
_COMMIT = "1281172539740afaa39d3d2aa7ece1f048df9682"
_ZERO = 0
_ONE_HUNDRED_PERCENT = 100.0
_SHA256_LENGTH = 64
_SUCCESSFUL_JOBS = 85
_CORE_PASS_COUNT = 10
_CORE_RUN_COUNT = 10_860
_EXTENDED_PASS_COUNT = 12
_EXTENDED_RUN_COUNT = 13_032
_PUBLIC_SAMPLE_COUNT = 360
_VM_FIXTURE_COUNT = 1_005


def _report() -> dict[str, Any]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_published_differential_run_binds_success_to_commit_and_run() -> None:
    report = _report()

    expect(
        report["workflow_run"] == _RUN_ID
        and report["commit"] == _COMMIT
        and report["workflow_jobs"] == {"completed": _SUCCESSFUL_JOBS, "successful": _SUCCESSFUL_JOBS, "failed": _ZERO}
    )


def test_published_differential_run_records_complete_seed_evidence() -> None:
    differential = _report()["differential"]

    expect(
        differential["core_pass_count"] == _CORE_PASS_COUNT
        and differential["core_classified_runs"] == _CORE_RUN_COUNT
        and differential["core_error_runs"] == _ZERO
        and differential["core_failed_seed_runs"] == _ZERO
        and differential["core_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
        and differential["extended_pass_count"] == _EXTENDED_PASS_COUNT
        and differential["extended_classified_runs"] == _EXTENDED_RUN_COUNT
        and differential["extended_error_runs"] == _ZERO
        and differential["extended_failed_seed_runs"] == _ZERO
        and differential["extended_semantic_success_percent"] == _ONE_HUNDRED_PERCENT
    )


def test_published_differential_run_records_public_corpus_results() -> None:
    report = _report()["public_compatibility"]
    aggregate = json.loads((_ROOT / "docs" / report["report"]).read_text(encoding="utf-8"))

    expect(
        report["status"] == aggregate["status"] == "passed"
        and report["sample_count"] == aggregate["sample_count"] == _PUBLIC_SAMPLE_COUNT
        and report["differential_failed_samples"] == aggregate["differential_failed_samples"] == 0
        and report["static_recovery_failed_samples"] == aggregate["static_recovery_failed_samples"] == 0
    )


def test_published_differential_run_records_preview_platform_results() -> None:
    report = _report()["platform_preview"]
    aggregate = json.loads((_ROOT / "docs" / report["summary_report"]).read_text(encoding="utf-8"))
    observed = {}

    for name, row in report["platform_reports"].items():
        root = ElementTree.parse(_ROOT / "docs" / row["file"]).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        observed[name] = {
            "tests": sum(int(suite.attrib.get("tests", "0")) for suite in suites),
            "failures": sum(int(suite.attrib.get("failures", "0")) for suite in suites),
            "errors": sum(int(suite.attrib.get("errors", "0")) for suite in suites),
            "skipped": sum(int(suite.attrib.get("skipped", "0")) for suite in suites),
            "file": row["file"],
        }

    expect(
        report["status"] == aggregate["summary"]["status"] == "complete"
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


def test_published_differential_run_binds_retained_platform_hashes() -> None:
    report = _report()
    retained = [artifact for artifact in report["source_artifacts"] if "retained_as" in artifact]

    expect(
        all(
            len(artifact["sha256"]) == _SHA256_LENGTH
            and hashlib.sha256((_ROOT / "docs" / artifact["retained_as"]).read_bytes()).hexdigest()
            == artifact["sha256"]
            for artifact in retained
        )
    )


def test_published_differential_run_records_vm_semantic_parity() -> None:
    semantic = _report()["vm_semantic"]

    expect(
        semantic["status"] == "passed"
        and semantic["fixture_count"]
        == semantic["passed_count"]
        == semantic["qemu_completed_pairs"]
        == _VM_FIXTURE_COUNT
        and semantic["failed_count"] == semantic["qemu_divergent_pairs"] == _ZERO
        and semantic["qemu_missing_pairs"] == semantic["qemu_unavailable_pairs"] == _ZERO
    )


def test_published_differential_run_does_not_expose_host_paths() -> None:
    report = _report()
    paths = [
        _REPORT_PATH,
        _ROOT / "docs" / report["public_compatibility"]["report"],
        _ROOT / "docs" / report["platform_preview"]["summary_report"],
        *(_ROOT / "docs" / row["file"] for row in report["platform_preview"]["platform_reports"].values()),
    ]
    serialized = "".join(path.read_text(encoding="utf-8") for path in paths)

    expect(not any(prefix in serialized for prefix in _HOST_PATH_PREFIXES))
