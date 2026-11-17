"""Verify the bounded current-source Ghidra benchmark evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_COMMIT = "8a612589dab88d4c928ea46ab8c525c305ef9184"
_SOURCE_TREE = "e824c2f52b5b98af214056efbe9e1ca9727cbd57"
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-local-ghidra-virtualization-2026-11-17-8a612589-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-local-ghidra-virtualization-2026-11-17-8a612589.json.gz"
_EXPECTED_FIXTURES = {
    "elf_switch_pie_x86_64": (13296, "2b2bebfbfe1bf50813f641eb0b26e44ca7cc430ff0c5064ecb3abdf5aab1357f"),
    "elf_vm_arith_x86_64": (4632, "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"),
    "elf_vm_fpengineidxnb_x86_64": (4728, "9f6971e93e6b3fd24f2f990b7dd273722b33044e65d2d89c113c184649675b07"),
    "elf_vm_movabs_x86_64": (4776, "9d67243e403eb5fc4f736bd7186f617691275fffacb0739b464ed6da068e19a3"),
}
_ZERO = 0
_FIXTURE_COUNT = 4
_EXPECTED_ANALYZER_ROWS = 36
_COMPLETED_ANALYZER_ROWS = 24
_UNAVAILABLE_ANALYZER_ROWS = 8
_ERROR_ANALYZER_ROWS = 4
_COMPLETION_PERCENT = 66.67
_GHIDRA_FUNCTION_DELTA = 5
_GHIDRA_ENTRYPOINT_DELTA = 5
_GHIDRA_LINE_DELTA = 74
_GHIDRA_BYTE_DELTA = 1059
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _report() -> dict[str, Any]:
    with gzip.open(_ARCHIVE_PATH, "rt", encoding="utf-8") as archived:
        return json.load(archived)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = _ZERO
    with gzip.open(path, "rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def test_local_ghidra_shard_archive_and_source_hashes_match() -> None:
    summary = _summary()
    archive = summary["archive"]
    uncompressed_sha256, uncompressed_bytes = _uncompressed_sha256(_ARCHIVE_PATH)

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_tree"] == _SOURCE_TREE
        and archive["path"] == str(_ARCHIVE_PATH.relative_to(_ROOT))
        and archive["sha256"] == _sha256(_ARCHIVE_PATH)
        and archive["uncompressed_sha256"] == uncompressed_sha256
        and archive["uncompressed_bytes"] == uncompressed_bytes
    )


def test_local_ghidra_shard_binds_exact_repository_fixtures() -> None:
    summary = _summary()
    fixture_records = summary["scope"]["fixtures"]

    expect(
        {row["name"]: (row["bytes"], row["sha256"]) for row in fixture_records} == _EXPECTED_FIXTURES
        and all(
            (fixture := _ROOT / "fixtures/dataset" / name).stat().st_size == size and _sha256(fixture) == digest
            for name, (size, digest) in _EXPECTED_FIXTURES.items()
        )
    )


def test_local_ghidra_shard_records_complete_ghidra_and_all_tool_slots() -> None:
    summary = _summary()
    report = _report()
    results = summary["results"]

    expect(
        summary["scope"]["pass_names"] == ["CodeVirtualization"]
        and summary["scope"]["expected_pass_runs"] == summary["scope"]["observed_pass_runs"] == _FIXTURE_COUNT
        and summary["scope"]["expected_tool_runs"] == summary["scope"]["observed_tool_runs"] == _EXPECTED_ANALYZER_ROWS
        and results["completed_tool_runs"] == _COMPLETED_ANALYZER_ROWS
        and results["completion_percent"] == _COMPLETION_PERCENT
        and results["unavailable_tool_runs"] == _UNAVAILABLE_ANALYZER_ROWS
        and results["error_tool_runs"] == _ERROR_ANALYZER_ROWS
        and results["missing_tool_runs"] == results["missing_pass_runs"] == _ZERO
        and all(sample["passes"][0]["status"] == "applied" for sample in report["samples"])
        and all(
            {tool["tool"]: tool["status"] for tool in sample["tools"]}
            == {
                "radare2": "completed",
                "objdump": "completed",
                "angr": "completed",
                "binary-ninja": "unavailable",
                "unicorn": "completed",
                "triton": "unavailable",
                "ida-pro": "error",
                "ghidra": "completed",
                "custom": "completed",
            }
            for sample in report["samples"]
        )
    )


def test_local_ghidra_shard_records_bounded_decompiler_deltas() -> None:
    ghidra = _summary()["results"]["ghidra"]

    expect(
        ghidra["completed_runs"] == _FIXTURE_COUNT
        and ghidra["function_delta"] == _GHIDRA_FUNCTION_DELTA
        and ghidra["decompiler_entrypoint_delta"] == _GHIDRA_ENTRYPOINT_DELTA
        and ghidra["decompiler_line_delta"] == _GHIDRA_LINE_DELTA
        and ghidra["decompiler_byte_delta"] == _GHIDRA_BYTE_DELTA
        and ghidra["duration_seconds"] > 0
    )


def test_local_ghidra_shard_keeps_incomplete_release_criteria_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    report_paths = [str(path.relative_to(_ROOT)) for path in (_SUMMARY_PATH, _ARCHIVE_PATH)]

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and all(path in evidence for path in report_paths)
        and _summary()["release_criteria"]["all_named_adversarial_analyzers"] == "open"
    )


def test_local_ghidra_shard_report_does_not_disclose_host_paths() -> None:
    trailing_bytes = b""
    with gzip.open(_ARCHIVE_PATH, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            content = trailing_bytes + chunk
            expect(_HOST_PATH.search(content) is None)
            trailing_bytes = content[-_PATH_CONTEXT_BYTES:]
