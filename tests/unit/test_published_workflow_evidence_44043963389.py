"""Verify the bounded public differential workflow evidence."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-workflow-evidence-2026-11-17-44043963389-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-workflow-evidence-2026-11-17-44043963389.tar.gz"
_SOURCE_COMMIT = "8a612589dab88d4c928ea46ab8c525c305ef9184"
_ZERO = 0
_SAMPLE_COUNT = 360
_SHARD_COUNT = 4
_TOOL_MEASUREMENT_COUNT = _SHARD_COUNT * 540
_PLATFORM_SLICE_COUNT = 5
_PLATFORM_CASE_COUNT = 76
_DIFFERENTIAL_CASES_PER_PASS = 3240
_EXPECTED_APPLIED = {
    "BlockReordering": 30,
    "CodeVirtualization": 234,
    "InstructionExpansion": 73,
    "InstructionSubstitution": 287,
    "NopInsertion": 84,
    "RegisterSubstitution": 5,
}
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _archive_files() -> dict[str, bytes]:
    with tarfile.open(_ARCHIVE_PATH, mode="r:gz") as archive:
        return {
            member.name: extracted.read()
            for member in archive.getmembers()
            if member.isfile() and (extracted := archive.extractfile(member)) is not None
        }


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _matrix_reports(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [json.loads(files[f"corpus/shards/{index}/matrix.json"]) for index in range(_SHARD_COUNT)]


def _pass_counts(matrices: list[dict[str, Any]], pass_name: str) -> dict[str, int]:
    rows = [row["passes"][pass_name] for matrix in matrices for row in matrix["records"]]
    cases = [case for row in rows for case in row["differential"]["cases"]]
    return {
        "samples": len(rows),
        "applied": sum(row["transformation"]["status"] == "applied" for row in rows),
        "omitted": sum(row["transformation"]["status"] == "omitted" for row in rows),
        "differential_cases": len(cases),
        "differential_failed": sum(not case["equivalent"] for case in cases),
    }


def test_workflow_evidence_archive_matches_its_hash_manifest() -> None:
    summary = _summary()
    archive = summary["archive"]
    files = _archive_files()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and archive["path"] == _ARCHIVE_PATH.relative_to(_ROOT).as_posix()
        and archive["sha256"] == _sha256(_ARCHIVE_PATH.read_bytes())
        and set(files) == {record["path"] for record in archive["files"]}
        and archive["bytes"] == _ARCHIVE_PATH.stat().st_size
    )


def test_workflow_evidence_archive_binds_each_original_report() -> None:
    files = _archive_files()
    manifest = _summary()["archive"]["files"]

    expect(
        all(
            len(files[record["path"]]) == record["bytes"] and _sha256(files[record["path"]]) == record["sha256"]
            for record in manifest
        )
    )


def test_workflow_public_corpus_records_differential_results_per_pass() -> None:
    files = _archive_files()
    matrices = _matrix_reports(files)
    results = _summary()["results"]
    per_pass = results["per_pass"]
    actual = {pass_name: _pass_counts(matrices, pass_name) for pass_name in _EXPECTED_APPLIED}

    expect(
        len(matrices) == _SHARD_COUNT
        and sum(len(matrix["records"]) for matrix in matrices) == _SAMPLE_COUNT
        and results["status"] == "passed"
        and results["built_samples"] == _SAMPLE_COUNT
        and results["failed_samples"] == results["differential_failed_samples"] == _ZERO
        and results["static_recovery_failed_samples"] == _ZERO
        and set(per_pass) == set(_EXPECTED_APPLIED)
        and all(
            item == actual[pass_name]
            and item["samples"] == _SAMPLE_COUNT
            and item["applied"] == _EXPECTED_APPLIED[pass_name]
            and item["omitted"] == _SAMPLE_COUNT - _EXPECTED_APPLIED[pass_name]
            and item["differential_cases"] == _DIFFERENTIAL_CASES_PER_PASS
            and item["differential_failed"] == _ZERO
            for pass_name, item in per_pass.items()
        )
    )


def test_workflow_optional_analyzers_remain_explicitly_omitted() -> None:
    files = _archive_files()
    tool_reports = [json.loads(files[f"corpus/shards/{index}/tools.json"]) for index in range(_SHARD_COUNT)]
    optional_names = {"angr", "binary_ninja", "ghidra", "ida_pro", "triton"}

    expect(
        _summary()["results"]["tool_measurements"]
        == sum(report["measured_samples"] for report in tool_reports)
        == _TOOL_MEASUREMENT_COUNT
        and _summary()["results"]["tool_failed_samples"] == _ZERO
        and all(report["status"] == "passed" for report in tool_reports)
        and all(set(report["optional_runners"]) == optional_names for report in tool_reports)
        and all(
            runner["status"] == "omitted" for report in tool_reports for runner in report["optional_runners"].values()
        )
    )


def test_workflow_cross_platform_smoke_is_bounded_and_complete() -> None:
    summary = _summary()["cross_platform_smoke"]

    expect(
        summary["status"] == "complete"
        and summary["complete_slices"] == summary["total_slices"] == _PLATFORM_SLICE_COUNT
        and summary["case_count"] == _PLATFORM_CASE_COUNT
        and summary["failure_count"] == summary["error_count"] == _ZERO
    )


def test_workflow_evidence_keeps_release_gates_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    paths = {path.relative_to(_ROOT).as_posix() for path in (_SUMMARY_PATH, _ARCHIVE_PATH)}
    criteria = readiness["criteria"]

    expect(
        all(
            criteria[name]["status"] == "open"
            for name in ("all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results")
        )
        and paths <= set(criteria["cross_platform_parity"]["evidence"])
        and paths <= set(criteria["all_named_adversarial_analyzers"]["evidence"])
        and all(
            _summary()["release_criteria"][name] == "open"
            for name in ("all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results")
        )
    )


def test_workflow_evidence_archive_contains_no_runner_host_paths() -> None:
    contents = b"\n".join(_archive_files().values())

    expect(_HOST_PATH.search(contents) is None)
