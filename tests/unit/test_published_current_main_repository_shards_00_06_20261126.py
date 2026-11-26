"""Pin current-main analyzer evidence for repository fixture shards 0 through 6."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_AGGREGATE = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-06-2026-11-26-summary.json"
_SHARD_SUMMARY = (
    _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-06-2026-11-26-06e2a344-summary.json"
)
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_06_20261126.py"
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_FIXTURES = {
    "elf_multiret_jccdiamond_x86_64": "01f9d0abab05f0d01ab8f8fc267a884d3fc4b53f17046ecfd9644aa9b4542134",
    "elf_vm_fparithriprel_x86_64": "21933e97626743bc489e0dbebc0065abe683baee373f9cfa77ae9f7e54d40a36",
    "elf_vm_gs_tlsidxnb_x86_64": "882b6ba50d1c9897119771aa1c9ac953471d7ed21389058d616ee75765001e64",
    "elf_vm_multiexit_x86_64": "da69f24e60ccd15355e16cae20df3e3d0358d6f068c37ca3f06a36fb2dc4515c",
    "elf_vm_simdmove_x86_64": "c6be2dd5a63c6a5f68fd63132d1e06c54084542ba53b1d958aef4fd98bf57455",
}
_EXPECTED_SHARD_COUNT = 7
_EXPECTED_SHARD_INDEX = 6
_EXPECTED_FIXTURE_COUNT = 37
_EXPECTED_PASS_ROWS = 814
_EXPECTED_ANALYZER_ROWS = 7_326
_EXPECTED_COMPLETED_ROWS = 5_698
_EXPECTED_UNAVAILABLE_ROWS = 1_628
_EXPECTED_ROWS_PER_TOOL = 110
_EXPECTED_SHARD_ANALYZER_ROWS = 990
_EXPECTED_SHARD_COMPLETED_ROWS = 770
_EXPECTED_SHARD_UNAVAILABLE_ROWS = 220


def test_seven_repository_shards_preserve_optional_analyzers_without_blocking() -> None:
    aggregate = json.loads(_AGGREGATE.read_text(encoding="utf-8"))
    shard_summary = json.loads(_SHARD_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    records = aggregate["shards"]
    record = next(item for item in records if item["shard_index"] == _EXPECTED_SHARD_INDEX)
    compressed = (_ROOT / record["raw_path"]).read_bytes()
    report = json.loads(gzip.decompress(compressed))
    scope = aggregate["scope"]
    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in report["samples"]
    }
    blockers = report["summary"]["adversarial_evidence_blockers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    completed_by_tool = {
        tool: sum(
            json.loads(gzip.decompress((_ROOT / item["raw_path"]).read_bytes()))["tool_summary"][tool]["completed"]
            for item in records
        )
        for tool in _EXPECTED_TOOLS
    }
    unavailable_by_tool = {
        tool: sum(
            json.loads(gzip.decompress((_ROOT / item["raw_path"]).read_bytes()))["tool_summary"][tool]["unavailable"]
            for item in records
        )
        for tool in _EXPECTED_TOOLS
    }
    evidence_paths = (
        _AGGREGATE.relative_to(_ROOT).as_posix(),
        _SHARD_SUMMARY.relative_to(_ROOT).as_posix(),
        record["raw_path"],
        _TEST_PATH,
    )

    expect(
        [item["shard_index"] for item in records] == list(range(_EXPECTED_SHARD_COUNT))
        and scope["fixture_shards"] == list(range(_EXPECTED_SHARD_COUNT))
        and scope["fixture_count"] == _EXPECTED_FIXTURE_COUNT
        and scope["expected_pass_runs"] == _EXPECTED_PASS_ROWS
        and scope["expected_tool_rows"] == _EXPECTED_ANALYZER_ROWS
        and scope["completed_tool_rows"] == _EXPECTED_COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _EXPECTED_UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"] == completed_by_tool
        and scope["unavailable_tool_runs_by_tool"] == unavailable_by_tool
        and completed_by_tool["ida-pro"] == completed_by_tool["ghidra"] == _EXPECTED_PASS_ROWS
        and unavailable_by_tool["triton"] == unavailable_by_tool["binary-ninja"] == _EXPECTED_PASS_ROWS
        and fixture_hashes == _EXPECTED_FIXTURES
        and {row["name"]: row["sha256"] for row in shard_summary["scope"]["fixtures"]} == _EXPECTED_FIXTURES
        and shard_summary["source_commit"] == record["source_commit"]
        and shard_summary["report"]["compressed_sha256"] == hashlib.sha256(compressed).hexdigest()
        and shard_summary["report"]["uncompressed_sha256"] == hashlib.sha256(gzip.decompress(compressed)).hexdigest()
        and report["summary"]["expected_tool_runs"] == _EXPECTED_SHARD_ANALYZER_ROWS
        and report["summary"]["completed_tool_runs"] == _EXPECTED_SHARD_COMPLETED_ROWS
        and report["summary"]["unavailable_tool_runs"] == _EXPECTED_SHARD_UNAVAILABLE_ROWS
        and report["tool_summary"]["binary-ninja"]["unavailable"] == _EXPECTED_ROWS_PER_TOOL
        and "binary-ninja" in report["summary"]["tools_without_full_completion"]
        and "binary-ninja" not in blockers["tools_without_full_completion"]
        and all(row["tool"] != "binary-ninja" for row in blockers["incomplete_tool_coverage"])
        and blockers["unavailable_tool_runs_by_tool"] == {"triton": _EXPECTED_ROWS_PER_TOOL}
        and aggregate["release_gate"]["all_named_adversarial_analyzers"] == "open"
        and aggregate["release_gate"]["optional_analyzers"] == ["binary-ninja"]
        and aggregate["release_gate"]["required_analyzers_unavailable"] == ["triton"]
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and all(path in criterion["evidence"] for path in evidence_paths)
    )
