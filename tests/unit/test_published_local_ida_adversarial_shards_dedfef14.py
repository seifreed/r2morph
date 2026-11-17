"""Validates current-source local analyzer shards and their bounded claims."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_COMMIT = "dedfef14f00bda1e8f90bae6759c7b55899c8b3d"
_SHARD_INDICES = (0, 1)
_EXPECTED_FIXTURES_PER_SHARD = 4
_EXPECTED_TOTAL_FIXTURES = 8
_EXPECTED_PASS_COUNT = 22
_EXPECTED_PASS_ROWS_PER_SHARD = 88
_EXPECTED_ANALYZER_ROWS_PER_SHARD = 792
_EXPECTED_COMPLETED_ROWS_PER_SHARD = 528
_EXPECTED_UNAVAILABLE_ROWS_PER_SHARD = 264
_EXPECTED_FIXTURES = {
    0: ("elf_switch_pie_x86_64", "elf_vm_arith_x86_64", "elf_vm_fpengineidxnb_x86_64", "elf_vm_movabs_x86_64"),
    1: ("elf_vm_leaidx_x86_64", "elf_vm_leaidxnb_x86_64", "elf_vm_pie_x86_64", "elf_vm_shift_x86_64"),
}
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _paths(index: int) -> tuple[Path, Path]:
    prefix = f"protection-adversarial-local-allpasses-shard-2026-11-17-dedfef14-{index:02d}"
    return _ROOT / "docs" / f"{prefix}-summary.json", _ROOT / "docs" / f"{prefix}.json.gz"


def _summary(index: int) -> dict[str, Any]:
    return json.loads(_paths(index)[0].read_text(encoding="utf-8"))


def _report(index: int) -> dict[str, Any]:
    with gzip.open(_paths(index)[1], "rt", encoding="utf-8") as report:
        return json.load(report)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_metadata(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = _ZERO
    with gzip.open(path, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def test_local_ida_shard_archives_match_hash_bound_summaries() -> None:
    expect(
        all(
            summary["archive"]["path"] == str(archive.relative_to(_ROOT))
            and summary["archive"]["sha256"] == _digest(archive)
            and summary["archive"]["uncompressed_sha256"] == _uncompressed_metadata(archive)[0]
            and summary["archive"]["uncompressed_bytes"] == _uncompressed_metadata(archive)[1]
            for index in _SHARD_INDICES
            for summary_path, archive in (_paths(index),)
            for summary in (json.loads(summary_path.read_text(encoding="utf-8")),)
        )
    )


def test_local_ida_shards_cover_disjoint_fixtures_and_complete_pass_rows() -> None:
    summaries = [_summary(index) for index in _SHARD_INDICES]
    reports = [_report(index) for index in _SHARD_INDICES]
    names = [fixture["name"] for summary in summaries for fixture in summary["scope"]["fixtures"]]

    expect(
        all(
            summary["source_commit"] == _SOURCE_COMMIT
            and summary["execution"]["platform"] == "darwin-arm64"
            and summary["scope"]["fixture_shard"] == {"count": 32, "index": index}
            and summary["scope"]["fixture_count"] == _EXPECTED_FIXTURES_PER_SHARD
            and tuple(fixture["name"] for fixture in summary["scope"]["fixtures"]) == _EXPECTED_FIXTURES[index]
            and all(
                fixture["bytes"] == (_ROOT / "fixtures" / "dataset" / fixture["name"]).stat().st_size
                and fixture["sha256"] == _digest(_ROOT / "fixtures" / "dataset" / fixture["name"])
                for fixture in summary["scope"]["fixtures"]
            )
            and summary["scope"]["pass_count"] == _EXPECTED_PASS_COUNT
            and summary["scope"]["expected_pass_runs"]
            == summary["scope"]["observed_pass_runs"]
            == _EXPECTED_PASS_ROWS_PER_SHARD
            and sum(len(sample["passes"]) for sample in report["samples"]) == _EXPECTED_PASS_ROWS_PER_SHARD
            and summary["results"]["pass_errors"] == _ZERO
            and summary["results"]["missing_pass_runs"] == _ZERO
            for index, summary, report in zip(_SHARD_INDICES, summaries, reports, strict=True)
        )
        and len(names) == len(set(names)) == _EXPECTED_TOTAL_FIXTURES
    )


def test_local_ida_shards_record_ida_completion_and_all_tool_slots() -> None:
    summaries = [_summary(index) for index in _SHARD_INDICES]
    reports = [_report(index) for index in _SHARD_INDICES]

    expect(
        all(
            summary["scope"]["expected_analyzer_runs"]
            == summary["scope"]["observed_analyzer_runs"]
            == _EXPECTED_ANALYZER_ROWS_PER_SHARD
            and summary["results"]["completed_analyzer_runs"] == _EXPECTED_COMPLETED_ROWS_PER_SHARD
            and summary["results"]["unavailable_analyzer_runs"] == _EXPECTED_UNAVAILABLE_ROWS_PER_SHARD
            and summary["results"]["analyzer_errors"] == _ZERO
            and summary["results"]["missing_analyzer_runs"] == _ZERO
            and summary["results"]["completed_runs_by_tool"]["ida-pro"] == _EXPECTED_PASS_ROWS_PER_SHARD
            and summary["results"]["unavailable_runs_by_tool"] == {"binary-ninja": 88, "ghidra": 88, "triton": 88}
            and sum(
                row["tool"] == "ida-pro" and row["status"] == "completed"
                for sample in report["samples"]
                for row in sample["tools"]
            )
            == _EXPECTED_PASS_ROWS_PER_SHARD
            for summary, report in zip(summaries, reports, strict=True)
        )
    )


def test_local_ida_shards_keep_analyzer_and_resistance_gates_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    paths = [str(path.relative_to(_ROOT)) for index in _SHARD_INDICES for path in _paths(index)]

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and all(path in evidence for path in paths)
        and all(
            _summary(index)["release_criteria"]["all_named_adversarial_analyzers"] == "open" for index in _SHARD_INDICES
        )
    )


def test_local_ida_shard_archives_do_not_disclose_host_paths() -> None:
    for index in _SHARD_INDICES:
        trailing_bytes = b""
        with gzip.open(_paths(index)[1], "rb") as report:
            for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
                content = trailing_bytes + chunk
                expect(_HOST_PATH.search(content) is None)
                trailing_bytes = content[-_PATH_CONTEXT_BYTES:]

    expect(True)
