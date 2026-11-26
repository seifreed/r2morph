"""Pin current-main analyzer evidence for repository fixture shards 0 through 7."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_AGGREGATE = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-07-2026-11-26-summary.json"
_SHARD_SUMMARY = (
    _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-07-2026-11-26-ba677ef7-summary.json"
)
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_07_20261126.py"
_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_FIXTURES = {
    "elf_nop_x86_64": "c06c0ec563215445d51a038376528fbae35b9e9146f340dce9c32937ae1652dd",
    "elf_vm_fpcmp_x86_64": "666139351a4d825bf216a7c940f2d89a7a9bc7b97c8760944f8724541768fa7e",
    "elf_vm_icall_x86_64": "1043efbdbbf3904826da651e847feabeed42e1c3b2162dd159f299a3a2053e69",
    "elf_vm_not_x86_64": "899b5afb3be437d0ec2e173f5de8f5120cb60e34c5f819ecc604b865f5e63c01",
    "elf_vm_simdwide_x86_64": "e07ad0461a41a76a7748c4a2ec53a122cf5db3b04252c380057961aad76db5b0",
}
_SHARD_COUNT = 8
_SHARD_INDEX = 7
_FIXTURE_COUNT = 42
_PASS_ROWS = 924
_ANALYZER_ROWS = 8_316
_COMPLETED_ROWS = 6_468
_UNAVAILABLE_ROWS = 1_848
_ROWS_PER_TOOL = 110
_SHARD_ANALYZER_ROWS = 990
_SHARD_COMPLETED_ROWS = 770
_SHARD_UNAVAILABLE_ROWS = 220


def test_eight_repository_shards_hash_bind_optional_analyzer_policy() -> None:
    aggregate = json.loads(_AGGREGATE.read_text(encoding="utf-8"))
    shard_summary = json.loads(_SHARD_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    records = aggregate["shards"]
    loaded = []
    for record in records:
        compressed = (_ROOT / record["raw_path"]).read_bytes()
        report = json.loads(gzip.decompress(compressed))
        expect(
            hashlib.sha256(compressed).hexdigest() == record["raw_sha256"]
            and report["fixture_shard"] == {"count": 32, "index": record["shard_index"]}
            and report["summary"]["error_tool_runs"] == 0
            and report["summary"]["missing_tool_runs"] == 0
            and report["summary"]["missing_pass_runs"] == 0
        )
        loaded.append((compressed, report))

    report = loaded[_SHARD_INDEX][1]
    compressed = loaded[_SHARD_INDEX][0]
    scope = aggregate["scope"]
    blockers = report["summary"]["adversarial_evidence_blockers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in report["samples"]
    }
    reports = [item for _compressed, item in loaded]
    completed_by_tool = {tool: sum(x["tool_summary"][tool]["completed"] for x in reports) for tool in _TOOLS}
    unavailable_by_tool = {tool: sum(x["tool_summary"][tool]["unavailable"] for x in reports) for tool in _TOOLS}
    evidence_paths = (
        _AGGREGATE.relative_to(_ROOT).as_posix(),
        _SHARD_SUMMARY.relative_to(_ROOT).as_posix(),
        aggregate["shards"][_SHARD_INDEX]["raw_path"],
        _TEST_PATH,
    )

    expect(
        [x["shard_index"] for x in records] == list(range(_SHARD_COUNT))
        and scope["fixture_shards"] == list(range(_SHARD_COUNT))
        and scope["fixture_count"] == _FIXTURE_COUNT
        and scope["expected_pass_runs"] == _PASS_ROWS
        and scope["expected_tool_rows"] == _ANALYZER_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"] == completed_by_tool
        and scope["unavailable_tool_runs_by_tool"] == unavailable_by_tool
        and completed_by_tool["ida-pro"] == completed_by_tool["ghidra"] == _PASS_ROWS
        and unavailable_by_tool["triton"] == unavailable_by_tool["binary-ninja"] == _PASS_ROWS
        and fixture_hashes == _FIXTURES
        and {row["name"]: row["sha256"] for row in shard_summary["scope"]["fixtures"]} == _FIXTURES
        and shard_summary["source_commit"] == records[_SHARD_INDEX]["source_commit"]
        and shard_summary["report"]["compressed_sha256"] == hashlib.sha256(compressed).hexdigest()
        and shard_summary["report"]["uncompressed_sha256"] == hashlib.sha256(gzip.decompress(compressed)).hexdigest()
        and report["summary"]["expected_tool_runs"] == _SHARD_ANALYZER_ROWS
        and report["summary"]["completed_tool_runs"] == _SHARD_COMPLETED_ROWS
        and report["summary"]["unavailable_tool_runs"] == _SHARD_UNAVAILABLE_ROWS
        and report["tool_summary"]["binary-ninja"]["unavailable"] == _ROWS_PER_TOOL
        and "binary-ninja" in report["summary"]["tools_without_full_completion"]
        and "binary-ninja" not in blockers["tools_without_full_completion"]
        and all(row["tool"] != "binary-ninja" for row in blockers["incomplete_tool_coverage"])
        and blockers["unavailable_tool_runs_by_tool"] == {"triton": _ROWS_PER_TOOL}
        and aggregate["release_gate"]["all_named_adversarial_analyzers"] == "open"
        and aggregate["release_gate"]["optional_analyzers"] == ["binary-ninja"]
        and aggregate["release_gate"]["required_analyzers_unavailable"] == ["triton"]
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and all(path in criterion["evidence"] for path in evidence_paths)
    )
