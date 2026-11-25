"""Pin current-source partial differential evidence from workflow 45528080704."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-differential-partial-2026-11-25-45528080704/summary.json"
_RUN_ID = 45528080704
_SOURCE_COMMIT = "da383ba850ad71c4a58cf68d15e1a35dff667770"
_ARTIFACT_ROWS_SHA256 = "5ce8e77478b86f34ced5ba3b922fb03711e20337fdf80e68ab95c20ed2e8d586"
_ARTIFACT_METADATA_COUNT = 73
_DOWNLOADED_ARTIFACT_COUNT = 67
_VM_EXPECTED_SHARDS = 24
_DIFFERENTIAL_EXPECTED_SHARDS = 48
_CAPTURED_DIFFERENTIAL_SHARDS = 19
_DIFFERENTIAL_SCHEMA_VERSION = 3
_FULL_EVIDENCE_PERCENT = 100.0
_PLATFORM_CASES = {
    "elf-arm32": 6,
    "elf-arm64": 7,
    "elf-x86-32": 8,
    "macos-arm64": 36,
    "macos-x86-64": 3,
    "windows-pe": 18,
}
_HOST_MARKERS = ("hostname=", "runnervm", "/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def _path(relative: str) -> Path:
    return _ROOT / relative


def _artifact_rows(summary: dict[str, object]) -> list[tuple[str, int, str, str, str]]:
    platform = summary["platform_preview"]["targets"]
    vm = summary["vm_semantic_preview"]["shards"]
    differential = summary["differential_shards"]
    rows = [*platform, *vm, *differential["core"]["reports"], *differential["extended"]["reports"]]
    return sorted(
        (
            row["artifact_name"],
            row["artifact_id"],
            row["artifact_digest"],
            row["report"],
            row["report_sha256"],
        )
        for row in rows
    )


def test_partial_snapshot_binds_workflow_source_and_downloaded_artifacts() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    rows = _artifact_rows(summary)
    artifact_manifest = json.dumps(rows, separators=(",", ":")).encode()

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["final_run_status"] == "cancelled"
        and workflow["captured_job_counts"]
        == {"total": 83, "completed_success": 51, "completed_failure": 0, "in_progress": 15, "queued": 17}
        and summary["artifact_collection"]["artifact_metadata_count"] == _ARTIFACT_METADATA_COUNT
        and summary["artifact_collection"]["downloaded_artifact_count"] == len(rows) == _DOWNLOADED_ARTIFACT_COUNT
        and hashlib.sha256(artifact_manifest).hexdigest() == _ARTIFACT_ROWS_SHA256
        and all(re.fullmatch(r"sha256:[0-9a-f]{64}", row[2]) for row in rows)
    )


def test_platform_slices_are_sanitized_and_all_captured_cases_passed() -> None:
    summary = _summary()
    targets = summary["platform_preview"]["targets"]

    expect(
        {row["target"]: row["counts"]["tests"] for row in targets} == _PLATFORM_CASES
        and summary["platform_preview"]["totals"]
        == {"targets": 6, "cases": 78, "passed": 78, "failures": 0, "errors": 0, "skipped": 0}
    )
    report_text = ""
    for row in targets:
        path = _path(row["report"])
        content = path.read_bytes()
        root = ElementTree.fromstring(content)
        cases = root.findall(".//testcase")
        expect(
            hashlib.sha256(content).hexdigest() == row["report_sha256"]
            and len(cases) == row["counts"]["tests"]
            and not root.findall(".//failure")
            and not root.findall(".//error")
            and not root.findall(".//skipped")
        )
        report_text += content.decode("utf-8")

    expect(not any(marker in report_text for marker in _HOST_MARKERS))


def test_vm_semantic_and_differential_partial_reports_have_complete_local_evidence() -> None:
    summary = _summary()
    vm = summary["vm_semantic_preview"]
    differential = summary["differential_shards"]

    expect(
        vm["expected_shards"] == _VM_EXPECTED_SHARDS
        and vm["totals"] == {"shards": 23, "fixtures": 963, "passed": 963, "failed": 0}
        and differential["expected_shards"] == _DIFFERENTIAL_EXPECTED_SHARDS
        and differential["core"]["totals"]
        == {
            "shards": 19,
            "classified_runs": 4320,
            "applied_runs": 1387,
            "errors": 0,
            "failed_seed_runs": 0,
            "semantic_failures": 0,
            "complete_evidence_runs": 4320,
            "complete_evidence_coverage_percent": 100.0,
        }
        and differential["extended"]["totals"]
        == {
            "shards": 19,
            "classified_runs": 5184,
            "applied_runs": 1360,
            "errors": 0,
            "failed_seed_runs": 0,
            "semantic_failures": 0,
            "complete_evidence_runs": 5184,
            "complete_evidence_coverage_percent": 100.0,
        }
    )

    for row in vm["shards"]:
        path = _path(row["report"])
        report = json.loads(path.read_text(encoding="utf-8"))
        expect(
            hashlib.sha256(path.read_bytes()).hexdigest() == row["report_sha256"]
            and report["measurement"] == "vm-semantic-native-parity-campaign"
            and report["target"] == {"architecture": "x86-64", "format": "ELF", "os": "linux"}
            and report["status"] == row["status"] == "passed"
            and report["fixture_count"] == row["fixture_count"] == row["passed_count"]
            and report["failed_count"] == row["failed_count"] == 0
        )

    for group in ("core", "extended"):
        reports = differential[group]["reports"]
        report_shards = {(row["shard"], row["seed"]) for row in reports}
        expect(len(reports) == _CAPTURED_DIFFERENTIAL_SHARDS and len(report_shards) == _CAPTURED_DIFFERENTIAL_SHARDS)
        for row in reports:
            path = _path(row["report"])
            packed = path.read_bytes()
            report = json.loads(gzip.decompress(packed))
            campaign = report["campaign_summary"]
            shard = campaign["corpus_scope"]["fixture_shard"]
            semantic_failures = sum(
                pass_report.get("semantic_failures", 0) for pass_report in report["summary"].values()
            )
            expect(
                hashlib.sha256(packed).hexdigest() == row["report_sha256"]
                and report["schema_version"] == row["schema_version"] == _DIFFERENTIAL_SCHEMA_VERSION
                and shard == {"count": 16, "index": row["shard"]}
                and row["classified_runs"] == campaign["total_seed_runs"]
                and row["applied_runs"] == campaign["total_applied_runs"]
                and row["errors"] == campaign["total_error_runs"] == 0
                and row["failed_seed_runs"] == campaign["total_failed_seed_runs"] == 0
                and row["semantic_failures"] == semantic_failures == 0
                and row["complete_evidence_runs"] == campaign["total_complete_evidence_runs"]
                and row["complete_evidence_coverage_percent"] == _FULL_EVIDENCE_PERCENT
            )


def test_partial_snapshot_keeps_full_release_gates_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    manifest_path = _SUMMARY.relative_to(_ROOT).as_posix()
    platform_paths = [row["report"] for row in summary["platform_preview"]["targets"]]
    correctness_paths = [
        *(row["report"] for row in summary["vm_semantic_preview"]["shards"]),
        *(row["report"] for group in ("core", "extended") for row in summary["differential_shards"][group]["reports"]),
    ]
    criteria = readiness["criteria"]

    expect(
        summary["readiness"]["cross_platform_parity"] == "open"
        and summary["readiness"]["all_named_adversarial_analyzers"] == "open"
        and summary["readiness"]["published_resistance_results"] == "open"
        and criteria["cross_platform_parity"]["status"] == "open"
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and all(path in criteria["cross_platform_parity"]["evidence"] for path in (manifest_path, *platform_paths))
        and all(
            path in criteria["published_correctness_results"]["evidence"]
            for path in (manifest_path, *correctness_paths)
        )
        and "45528080704" in (_ROOT / "README.md").read_text(encoding="utf-8")
    )
