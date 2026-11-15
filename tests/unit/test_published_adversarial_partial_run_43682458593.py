"""Regression checks for hash-bound partial adversarial run evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"
_SUMMARY_PATH = _DOCS / "protection-adversarial-partial-run-2026-11-15-43682458593-summary.json"
_ARCHIVE_PATH = _DOCS / "protection-adversarial-partial-run-2026-11-15-43682458593.json.gz"
_EXPECTED_RUN = 43_682_458_593
_EXPECTED_SOURCE = "13ac80258a5a51e0c872abe600bc04f52366ba0c"
_EXPECTED_BASE_COMMIT = "fb531485bf576c78cc72a438c6472d4d2f01287b"
_STANDALONE_SHARD_INDEX = 6
_EXPECTED_PASS_COUNT = 22
_EXPECTED_SHARDS = (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 23, 25, 27, 28, 29, 31)
_EXPECTED_SAMPLE_COUNT = 192
_EXPECTED_TOOL_RUNS = 38_016
_COMPLETED_TOOL_RUNS = 29_150
_UNAVAILABLE_TOOL_RUNS = 8_866
_UNICORN_COMPLETED_RUNS = 3_806
_UNICORN_UNAVAILABLE_RUNS = 418
_EXPECTED_TOOLS = {
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
}
_HOST_PATH_PREFIXES = (b"/home/", b"/runner/", b"/Users/", b"/private/", b"/opt/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _bundle() -> dict[str, object]:
    return json.loads(gzip.decompress(_ARCHIVE_PATH.read_bytes()))


def _report_bytes(shard_index: int) -> bytes:
    shard = _summary()["shards"][str(shard_index)]
    report = shard["report"]
    if report["archive_member"] is not None:
        return _bundle()["reports"][str(shard_index)].encode("utf-8")
    return (_ROOT / report["path"]).read_bytes()


def test_adversarial_partial_run_manifest_binds_archive_to_source_and_run() -> None:
    summary = _summary()
    archive_bytes = _ARCHIVE_PATH.read_bytes()
    expect(
        summary["workflow_run"] == _EXPECTED_RUN
        and summary["source_commit"] == _EXPECTED_SOURCE
        and summary["generated_against_commit"] == _EXPECTED_BASE_COMMIT
        and summary["benchmark_source_unchanged_since_source_commit"] is True
        and not any(
            path.startswith(("r2morph/", "fixtures/", "scripts/adversarial_benchmark"))
            or path in {"pyproject.toml", ".github/workflows/adversarial-benchmark.yml"}
            for path in summary["changed_paths_since_source_commit"]
        )
        and summary["archive"]
        == {
            "path": _ARCHIVE_PATH.relative_to(_ROOT).as_posix(),
            "sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "size_bytes": len(archive_bytes),
            "report_count": len(_EXPECTED_SHARDS) - 1,
            "report_format": "UTF-8 JSON strings keyed by shard index in a gzip-compressed JSON bundle",
        }
    )


def test_adversarial_partial_run_reports_match_completed_shard_jobs() -> None:
    summary = _summary()
    bundle = _bundle()
    shards = summary["shards"]
    expect(
        bundle["workflow_run"] == _EXPECTED_RUN
        and bundle["source_commit"] == _EXPECTED_SOURCE
        and set(shards) == {str(index) for index in _EXPECTED_SHARDS}
        and set(bundle["reports"]) == {str(index) for index in _EXPECTED_SHARDS if index != _STANDALONE_SHARD_INDEX}
        and all(
            shards[str(index)]["job"]["conclusion"] == "success"
            and shards[str(index)]["fixture_shard"] == {"count": 32, "index": index}
            and shards[str(index)]["pass_count"] == _EXPECTED_PASS_COUNT
            and shards[str(index)]["expected_tool_count"] == len(_EXPECTED_TOOLS)
            and shards[str(index)]["report"]["sha256"] == hashlib.sha256(_report_bytes(index)).hexdigest()
            and shards[str(index)]["report"]["size_bytes"] == len(_report_bytes(index))
            for index in _EXPECTED_SHARDS
        )
    )


def test_adversarial_partial_run_aggregates_all_rows_without_gaps_or_errors() -> None:
    summary = _summary()
    aggregate = summary["aggregate"]
    report_summaries = [json.loads(_report_bytes(index))["summary"] for index in _EXPECTED_SHARDS]
    expect(
        summary["completed_shard_indices"] == list(_EXPECTED_SHARDS)
        and aggregate["sample_count"] == _EXPECTED_SAMPLE_COUNT
        and aggregate["expected_tool_runs"] == sum(item["expected_tool_runs"] for item in report_summaries)
        and aggregate["completed_tool_runs"] == sum(item["completed_tool_runs"] for item in report_summaries)
        and aggregate["unavailable_tool_runs"] == sum(item["unavailable_tool_runs"] for item in report_summaries)
        and aggregate["missing_tool_runs"] == aggregate["error_tool_runs"] == 0
        and aggregate["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and aggregate["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and aggregate["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and len(
            {sample["original"] for index in _EXPECTED_SHARDS for sample in json.loads(_report_bytes(index))["samples"]}
        )
        == aggregate["sample_count"]
    )


def test_adversarial_partial_run_preserves_analyzer_limits_and_release_gates() -> None:
    summary = _summary()
    readiness = json.loads((_DOCS / "one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    report_bytes = [_report_bytes(index) for index in _EXPECTED_SHARDS]
    expect(
        set(summary["expected_tools"]) == _EXPECTED_TOOLS
        and summary["aggregate"]["completed_tool_runs_by_tool"]["binary-ninja"] == 0
        and summary["aggregate"]["unavailable_tool_runs_by_tool"]["binary-ninja"]
        == _EXPECTED_SAMPLE_COUNT * _EXPECTED_PASS_COUNT
        and summary["aggregate"]["unavailable_tool_runs_by_tool"]["ida-pro"]
        == _EXPECTED_SAMPLE_COUNT * _EXPECTED_PASS_COUNT
        and summary["aggregate"]["completed_tool_runs_by_tool"]["unicorn"] == _UNICORN_COMPLETED_RUNS
        and summary["aggregate"]["unavailable_tool_runs_by_tool"]["unicorn"] == _UNICORN_UNAVAILABLE_RUNS
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _SUMMARY_PATH.relative_to(_ROOT).as_posix() in evidence
        and _ARCHIVE_PATH.relative_to(_ROOT).as_posix() in evidence
        and all(not any(prefix in raw for prefix in _HOST_PATH_PREFIXES) for raw in report_bytes)
    )
