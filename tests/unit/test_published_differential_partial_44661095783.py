"""Pin current-source partial differential evidence from workflow 44661095783."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-differential-partial-2026-11-20-44661095783/summary.json"
_RUN_ID = 44661095783
_SOURCE_COMMIT = "f319f1e4c47f80b678b8a397dcdbcb0fa1d17f87"
_MATURITY_SCHEMA_VERSION = 3
_FIXTURE_SHARD_COUNT = 16
_PLATFORM_CASES = {"windows-pe": 18, "elf-arm32": 6, "elf-arm64": 7, "elf-x86-32": 8}
_ARTIFACTS = {
    "cross-platform-differential-windows-pe-44661095783-1": (
        14595702320,
        "sha256:5eb1ef50bedd4b0c073fc977c317f1c4a94479067f851d80b6b098d3e28cd020",
    ),
    "elf-arm-32-native-44661095783-1": (
        14595088360,
        "sha256:216332ea58c4ee813782f70faf3f7793e1c577e32d65db6207abf5b0f6a071a5",
    ),
    "elf-arm64-native-44661095783-1": (
        14596360145,
        "sha256:6881c6858bbc80073763bdf6d702f925c4e53dc57acbfab9bbc86b53ddc0c6dc",
    ),
    "elf-x86-32-native-44661095783-1": (
        14595661920,
        "sha256:09631a3d569de528baec6b8c3eef075338cd12a9cceee7226e882eab00f2a58e",
    ),
    "differential-corpus-by-pass-7-20260902-44661095783-1": (
        14596027885,
        "sha256:d0aae41dd310359e94e6fb59264761e1a3cc7cfa81190cf6932ef13718b34b95",
    ),
    "extended-maturity-passes-7-20260902-44661095783-1": (
        14595793418,
        "sha256:66a5401248a01f4ce4487efd2276297bd47941f8eb991824f20dacbdd57c31b6",
    ),
    "vm-semantic-campaign-20260916-1-44661095783-1": (
        14595269705,
        "sha256:376a4d1303c99d510471494cd7ae35e8854b81f0a3c059574cad7bc877472c9e",
    ),
    "vm-semantic-campaign-20260916-2-44661095783-1": (
        14595918516,
        "sha256:a62b446c1f647df57303ba3c25efc6d5f2d3ce8d4bc39e21b89566706924d613",
    ),
    "vm-semantic-campaign-20260916-3-44661095783-1": (
        14596226290,
        "sha256:0b076f969c9d4a5763ae982f8965e9ce2920bb0ba0041b675d4a65f2ffee580d",
    ),
    "vm-semantic-campaign-20260917-1-44661095783-1": (
        14595902763,
        "sha256:ea65e381c379d1e85561006cb08d5fc0522105a16cd9eec6e906c6def0a62f11",
    ),
    "vm-semantic-campaign-20260917-3-44661095783-1": (
        14596376003,
        "sha256:aa2d15ee734028d5d99ac009cba87c81132f234127778adcf7623af84f3e9e67",
    ),
    "vm-semantic-campaign-20260917-5-44661095783-1": (
        14595049831,
        "sha256:5803bd3bd1a79ff05eca9b635206ea99c70b5ad7cb23dd1e884690137070e38f",
    ),
    "vm-semantic-campaign-20260917-7-44661095783-1": (
        14595158658,
        "sha256:8466c0bf6b43a8d82d304dd30e14f6b53a3b6965d9104665e936bdbc8ebd057c",
    ),
    "vm-semantic-campaign-20260918-0-44661095783-1": (
        14596256082,
        "sha256:096f4cf6e3791a697bd5709de3b0517950616aa9ab746453517e84f951f041d6",
    ),
    "vm-semantic-campaign-20260918-2-44661095783-1": (
        14596257624,
        "sha256:c8425c35be9f9f2e51da1507d3b7a36adfc09d30bb79e756e25d61e356274440",
    ),
    "vm-semantic-campaign-20260918-3-44661095783-1": (
        14595753654,
        "sha256:78fda53d12ece36eda7a0b540bc2941386fc36f89b4501e351963ae92f1f2dfb",
    ),
    "vm-semantic-campaign-20260918-4-44661095783-1": (
        14595746970,
        "sha256:3d2b51440f990b8642befe9c083f8c60300a27d5a000e2ca05bca4e329ce3233",
    ),
}


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def _report_path(relative_path: str) -> Path:
    return _ROOT / relative_path


def test_snapshot_binds_partial_results_to_current_source_and_workflow_artifacts() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    artifact_rows = [
        *summary["platform_preview"]["targets"],
        *summary["vm_semantic_preview"]["shards"],
        summary["differential_shard"]["core_report"],
        summary["differential_shard"]["extended_report"],
    ]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["captured_job_counts"]
        == {"total": 81, "completed_success": 16, "completed_failure": 0, "in_progress": 13, "queued": 52}
        and {row["artifact_name"]: (row["artifact_id"], row["artifact_digest"]) for row in artifact_rows} == _ARTIFACTS
    )


def test_platform_snapshot_records_only_passed_available_targets() -> None:
    summary = _summary()
    preview = summary["platform_preview"]

    expect(
        {row["target"]: row["cases"] for row in preview["targets"]} == _PLATFORM_CASES
        and preview["totals"] == {"targets": 4, "cases": 39, "passed": 39, "failures": 0, "errors": 0, "skipped": 0}
    )
    for row in preview["targets"]:
        report_path = _report_path(row["report"])
        root = ElementTree.parse(report_path).getroot()
        cases = root.findall(".//testcase")
        failures = root.findall(".//failure")
        errors = root.findall(".//error")
        skipped = root.findall(".//skipped")
        expect(
            hashlib.sha256(report_path.read_bytes()).hexdigest() == row["sha256"]
            and len(cases) == row["cases"] == row["passed"]
            and not failures
            and not errors
            and not skipped
        )


def test_vm_semantic_and_differential_shards_have_complete_bounded_evidence() -> None:
    summary = _summary()
    vm = summary["vm_semantic_preview"]
    differential = summary["differential_shard"]

    expect(vm["totals"] == {"shards": 11, "fixtures": 461, "passed": 461, "failed": 0})
    for row in vm["shards"]:
        path = _report_path(row["report"])
        report = json.loads(path.read_text(encoding="utf-8"))
        expect(
            hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
            and report["measurement"] == "vm-semantic-native-parity-campaign"
            and report["target"] == {"architecture": "x86-64", "format": "ELF", "os": "linux"}
            and report["status"] == row["status"] == "passed"
            and report["fixture_count"] == row["fixture_count"] == row["passed_count"]
            and report["failed_count"] == row["failed_count"] == 0
        )

    for key, expected in (
        (
            "core_report",
            {
                "classified_runs": 230,
                "applied_runs": 76,
                "errors": 0,
                "semantic_failures": 0,
                "complete_evidence_runs": 230,
                "complete_evidence_coverage_percent": 100.0,
                "core_passes": 10,
                "expected_core_passes": 10,
            },
        ),
        (
            "extended_report",
            {
                "classified_runs": 276,
                "applied_runs": 71,
                "errors": 0,
                "complete_evidence_runs": 276,
                "complete_evidence_coverage_percent": 100.0,
                "extended_passes": 12,
                "expected_extended_passes": 12,
            },
        ),
    ):
        row = differential[key]
        path = _report_path(row["path"])
        report = json.loads(gzip.decompress(path.read_bytes()))
        expect(
            hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
            and report["schema_version"] == _MATURITY_SCHEMA_VERSION
            and report["campaign_summary"]["corpus_scope"]["fixture_shard"]
            == {"count": _FIXTURE_SHARD_COUNT, "index": 7}
            and all(row[field] == value for field, value in expected.items())
        )


def test_partial_snapshot_keeps_unfinished_release_criteria_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["readiness"]
        == {
            "cross_platform_parity": "open",
            "all_named_adversarial_analyzers": "open",
            "published_resistance_results": "open",
            "reason": "This is an in-progress partial snapshot, not the campaign aggregate or full matrix.",
        }
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix() in readiness["criteria"]["cross_platform_parity"]["evidence"]
    )
