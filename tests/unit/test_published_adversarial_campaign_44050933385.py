"""Verify the current-source 32-shard adversarial campaign evidence."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-2026-11-17-44050933385-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-2026-11-17-44050933385.tar.gz"
_SOURCE_COMMIT = "8a612589dab88d4c928ea46ab8c525c305ef9184"
_SHARD_COUNT = 32
_AGGREGATE_JOB_ID = 133987828440
_SAMPLE_COUNT = 362
_PASS_ROW_COUNT = 7964
_TOOL_ROW_COUNT = 71676
_COMPLETED_TOOL_ROWS = 55220
_UNAVAILABLE_TOOL_ROWS = 16456
_UNICORN_UNAVAILABLE_ROWS = 528
_RESISTANCE_SEEDS = 10
_DISPATCH_VARIANTS = 2
_NEAR_SIMILARITY_COUNT = 388
_SIMILARITY_COMPARISONS = 2295
_RESISTANCE_FIXTURES = 15
_PROGRESSIVE_GROWTH_FIXTURES = 6
_ZERO = 0
_EXPECTED_APPLIED_BY_PASS = {
    "APIHashing": 24,
    "AntiDisassembly": 58,
    "BlockReordering": 13,
    "CodeMobility": 187,
    "CodeVirtualization": 362,
    "ConstantUnfolding": 219,
    "ControlFlowFlattening": 51,
    "DataFlowMutation": 28,
    "DeadCodeInjection": 55,
    "FunctionOutlining": 178,
    "ImportObfuscation": 177,
    "InstructionExpansion": 20,
    "InstructionSubstitution": 216,
    "NopInsertion": 23,
    "OpaquePredicates": 190,
    "PatternSubstitution": 211,
    "PolymorphicEngine": 233,
    "RegisterSubstitution": 8,
    "SelfModifyingCode": 35,
    "ShortJumpPatching": 12,
    "StackStrings": 6,
    "StringObfuscation": 37,
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


def _benchmark_reports(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [json.loads(files[f"adversarial/shards/{shard:02d}.json"]) for shard in range(_SHARD_COUNT)]


def _tool_counts(reports: list[dict[str, Any]], status: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for report in reports:
        key = f"{status}_tool_runs_by_tool"
        for name, count in report["summary"].get(key, {}).items():
            result[name] = result.get(name, _ZERO) + count
    return result


def _pass_counts(reports: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    fields = ("samples", "applied", "no_op", "omitted", "errors", "partial_virtualization")
    result = {name: {field: 0 for field in fields} for name in _EXPECTED_APPLIED_BY_PASS}
    for report in reports:
        for name, counts in report["pass_summary"].items():
            for field in result[name]:
                result[name][field] += counts.get(field, 0)
    return result


def test_adversarial_campaign_archive_matches_its_hash_manifest() -> None:
    summary = _summary()
    archive = summary["archive"]
    files = _archive_files()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow"]["shard_jobs"] == _SHARD_COUNT
        and summary["workflow"]["aggregate_job_status"] == "success"
        and summary["workflow"]["aggregate_job_id"] == _AGGREGATE_JOB_ID
        and archive["path"] == _ARCHIVE_PATH.relative_to(_ROOT).as_posix()
        and archive["sha256"] == hashlib.sha256(_ARCHIVE_PATH.read_bytes()).hexdigest()
        and set(files) == {record["path"] for record in archive["files"]}
        and archive["bytes"] == _ARCHIVE_PATH.stat().st_size
    )


def test_adversarial_campaign_archive_binds_every_report() -> None:
    files = _archive_files()
    manifest = _summary()["archive"]["files"]

    expect(
        all(
            len(files[record["path"]]) == record["bytes"]
            and hashlib.sha256(files[record["path"]]).hexdigest() == record["sha256"]
            for record in manifest
        )
    )


def test_adversarial_campaign_records_all_pass_and_tool_rows() -> None:
    reports = _benchmark_reports(_archive_files())
    scope = _summary()["scope"]
    results = _summary()["results"]

    expect(
        len(reports) == _SHARD_COUNT
        and sum(report["sample_count"] for report in reports) == scope["samples"] == _SAMPLE_COUNT
        and sum(report["summary"]["observed_pass_runs"] for report in reports) == scope["pass_rows"] == _PASS_ROW_COUNT
        and sum(report["summary"]["observed_tool_runs"] for report in reports)
        == scope["observed_tool_rows"]
        == _TOOL_ROW_COUNT
        and results["completed_tool_runs"] == _COMPLETED_TOOL_ROWS
        and results["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_ROWS
        and results["error_tool_runs"] == results["missing_tool_runs"] == _ZERO
        and results["error_pass_runs"] == results["missing_pass_runs"] == _ZERO
    )


def test_adversarial_campaign_pass_application_counts_match_shards() -> None:
    reports = _benchmark_reports(_archive_files())
    actual = _pass_counts(reports)
    expected = _summary()["results"]["per_pass"]

    expect(
        set(actual) == set(_EXPECTED_APPLIED_BY_PASS)
        and all(actual[name] == expected[name] for name in actual)
        and all(actual[name]["samples"] == _SAMPLE_COUNT for name in actual)
        and all(actual[name]["applied"] == count for name, count in _EXPECTED_APPLIED_BY_PASS.items())
        and all(actual[name]["errors"] == _ZERO for name in actual)
    )


def test_adversarial_campaign_analyzer_limits_are_explicit() -> None:
    reports = _benchmark_reports(_archive_files())
    summary = _summary()
    results = summary["results"]
    completed = _tool_counts(reports, "completed")
    unavailable = _tool_counts(reports, "unavailable")

    expect(
        completed
        == {
            "angr": _PASS_ROW_COUNT,
            "custom": _PASS_ROW_COUNT,
            "ghidra": _PASS_ROW_COUNT,
            "objdump": _PASS_ROW_COUNT,
            "radare2": _PASS_ROW_COUNT,
            "triton": _PASS_ROW_COUNT,
            "unicorn": _PASS_ROW_COUNT - _UNICORN_UNAVAILABLE_ROWS,
        }
        and unavailable
        == {
            "binary-ninja": _PASS_ROW_COUNT,
            "ida-pro": _PASS_ROW_COUNT,
            "unicorn": _UNICORN_UNAVAILABLE_ROWS,
        }
        and results["per_tool"]["ghidra"] == {"completed": _PASS_ROW_COUNT, "unavailable": _ZERO, "error": _ZERO}
        and results["per_tool"]["triton"] == {"completed": _PASS_ROW_COUNT, "unavailable": _ZERO, "error": _ZERO}
        and results["per_tool"]["binary-ninja"]["unavailable"] == _PASS_ROW_COUNT
        and results["per_tool"]["ida-pro"]["unavailable"] == _PASS_ROW_COUNT
        and results["per_tool"]["unicorn"]["unavailable"] == _UNICORN_UNAVAILABLE_ROWS
        and summary["workflow"]["aggregate_job_status"] == "success"
    )


def test_adversarial_campaign_resistance_data_retains_its_limits() -> None:
    results = _summary()["vm_resistance_smoke"]

    expect(
        results["seed_count"] == _RESISTANCE_SEEDS
        and results["opcode_assignment_unique_count"] == _RESISTANCE_SEEDS
        and results["dispatch_variant_unique_count"] == _DISPATCH_VARIANTS
        and results["cross_seed_exact_normalised_matches"] == _ZERO
        and results["cross_seed_nearest_similarity_above_threshold"] == _NEAR_SIMILARITY_COUNT
        and results["cross_seed_nearest_similarity_comparisons"] == _SIMILARITY_COMPARISONS
        and results["fixture_count"] == _RESISTANCE_FIXTURES
        and results["seed_count_per_fixture"] == _RESISTANCE_SEEDS
        and results["semantic_parity"] is True
        and results["tamper_probes_diverged"] is True
        and results["distinct_artifacts"] is True
        and results["progressive_growth_supported_fixtures"] == _PROGRESSIVE_GROWTH_FIXTURES
        and results["human_review_status"] == "pending-human-adversarial-review"
    )


def test_adversarial_campaign_keeps_incomplete_release_gates_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence_paths = {path.relative_to(_ROOT).as_posix() for path in (_SUMMARY_PATH, _ARCHIVE_PATH)}
    criteria = readiness["criteria"]

    expect(
        criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and criteria["cross_platform_parity"]["status"] == "open"
        and evidence_paths <= set(criteria["all_named_adversarial_analyzers"]["evidence"])
        and evidence_paths <= set(criteria["published_resistance_results"]["evidence"])
        and all(value == "open" for value in _summary()["release_criteria"].values())
    )


def test_adversarial_campaign_reports_contain_no_host_paths() -> None:
    contents = b"\n".join(_archive_files().values())

    expect(_HOST_PATH.search(contents) is None)
