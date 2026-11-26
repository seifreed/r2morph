"""Pin current-main analyzer evidence for repository fixture shards 0 through 8."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_AGGREGATE = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-08-2026-11-26-summary.json"
_SHARD_SUMMARY = (
    _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-08-2026-11-26-3eead60d-summary.json"
)
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_08_20261126.py"
_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_FIXTURES = {
    "elf_switch_abs_x86_64": "239196a8c3dc3cf1f83c709a15d30a4d4bc9beef2f47decad058add945a9fc39",
    "elf_vm_fpcmpidxnb_x86_64": "a7c39f63c519e85c4770f02d0170a6f7a27a7b4c61d50cbaa73477e211b5be17",
    "elf_vm_idxcall_x86_64": "ff13e30faa03f2eb1766ee6a4e1790b04c85f825d0077f2074cb1de329f1535c",
    "elf_vm_opmem_x86_64": "3a2ca2c54b03f9f597de5ef2de3a997d8876fc4edf463f0a551aee6cc27a783f",
    "elf_vm_subflagdead_x86_64": "0fd0d37f29aa12ce0733502c56a687e7ff7baef8e7f4b523895922d35fc5fa94",
}
_SHARD_COUNT = 9
_SHARD_INDEX = 8
_FIXTURE_COUNT = 47
_PASS_ROWS = 1_034
_ANALYZER_ROWS = 9_306
_COMPLETED_ROWS = 7_238
_UNAVAILABLE_ROWS = 2_068
_SHARD_ANALYZER_ROWS = 990
_SHARD_COMPLETED_ROWS = 770
_SHARD_UNAVAILABLE_ROWS = 220
_ROWS_PER_TOOL = 110


def test_nine_repository_shards_hash_bind_optional_analyzer_policy() -> None:
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

    compressed, report = loaded[_SHARD_INDEX]
    scope = aggregate["scope"]
    blockers = report["summary"]["adversarial_evidence_blockers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in report["samples"]
    }
    reports = [item for _compressed, item in loaded]
    completed = {tool: sum(x["tool_summary"][tool]["completed"] for x in reports) for tool in _TOOLS}
    unavailable = {tool: sum(x["tool_summary"][tool]["unavailable"] for x in reports) for tool in _TOOLS}
    evidence = (
        _AGGREGATE.relative_to(_ROOT).as_posix(),
        _SHARD_SUMMARY.relative_to(_ROOT).as_posix(),
        records[_SHARD_INDEX]["raw_path"],
        _TEST_PATH,
    )

    expect(
        [item["shard_index"] for item in records] == list(range(_SHARD_COUNT))
        and scope["fixture_shards"] == list(range(_SHARD_COUNT))
        and scope["fixture_count"] == _FIXTURE_COUNT
        and scope["expected_pass_runs"] == _PASS_ROWS
        and scope["expected_tool_rows"] == _ANALYZER_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"] == completed
        and scope["unavailable_tool_runs_by_tool"] == unavailable
        and completed["ida-pro"] == completed["ghidra"] == _PASS_ROWS
        and unavailable["triton"] == unavailable["binary-ninja"] == _PASS_ROWS
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
        and all(path in criterion["evidence"] for path in evidence)
    )
