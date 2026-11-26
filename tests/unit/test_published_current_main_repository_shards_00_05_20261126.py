"""Pin current-main analyzer evidence for repository fixture shards 0 through 5."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_AGGREGATE = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-05-2026-11-26-summary.json"
_SHARD_05_SUMMARY = (
    _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-05-2026-11-26-2cf345c8-summary.json"
)
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_05_20261126.py"
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_SHARD_INDEX = 5
_EXPECTED_FIXTURE_COUNT = 32
_EXPECTED_PASS_ROWS = 704
_EXPECTED_ANALYZER_ROWS = 6_336
_EXPECTED_COMPLETED_ROWS = 4_928
_EXPECTED_UNAVAILABLE_ROWS = 1_408
_EXPECTED_SHARD_ANALYZER_ROWS = 990
_EXPECTED_SHARD_COMPLETED_ROWS = 770
_EXPECTED_SHARD_UNAVAILABLE_ROWS = 220
_EXPECTED_ROWS_PER_TOOL = 110
_EXPECTED_FIXTURES = {
    "elf_jumpchain_x86_64": "dfa20b39d8b66ff3fa4e45417429b0158b827512b19525641278be6a4b895390",
    "elf_vm_fparithmem_x86_64": "53f59e8087a1a13d5744bcd41378a157d2c5d407672bc4ee55292badbf8c9f01",
    "elf_vm_gs_tls_x86_64": "d940a9eac2236026e34c973542bb1a5a07096d7fca09d2ae7d0ff641f4c67136",
    "elf_vm_movxreg_x86_64": "46f0e338deeaa244ae8a2fa95c3014af5b25f4b82854a1e1f12c0a312df7da7d",
    "elf_vm_simdintarith_x86_64": "f06a02de35f80a5ec275ebd4c5a91e9c6da1c1d4e25781d2717acca460020d4a",
}


def _read_record(record: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    compressed = (_ROOT / record["raw_path"]).read_bytes()
    report = json.loads(gzip.decompress(compressed))
    expect(
        hashlib.sha256(compressed).hexdigest() == record["raw_sha256"]
        and report["fixture_shard"] == {"count": 32, "index": record["shard_index"]}
        and report["summary"]["missing_pass_runs"] == report["summary"]["missing_tool_runs"] == 0
        and report["summary"]["error_tool_runs"] == 0
    )
    return compressed, report


def test_six_repository_shards_have_hash_bound_aggregate_and_optional_analyzer_evidence() -> None:
    aggregate = json.loads(_AGGREGATE.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    shard_summary = json.loads(_SHARD_05_SUMMARY.read_text(encoding="utf-8"))
    records = aggregate["shards"]
    loaded = [_read_record(record) for record in records]
    reports = [report for _compressed, report in loaded]
    scope = aggregate["scope"]
    shard_05_record = next(record for record in records if record["shard_index"] == _EXPECTED_SHARD_INDEX)
    shard_05_bytes, shard_05_report = loaded[5]
    shard_05 = shard_summary["scope"]
    blocker = shard_05_report["summary"]["adversarial_evidence_blockers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in shard_05_report["samples"]
    }
    completed_by_tool = {
        tool: sum(report["tool_summary"][tool]["completed"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    unavailable_by_tool = {
        tool: sum(report["tool_summary"][tool]["unavailable"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    evidence_paths = (
        _AGGREGATE.relative_to(_ROOT).as_posix(),
        _SHARD_05_SUMMARY.relative_to(_ROOT).as_posix(),
        shard_05_record["raw_path"],
        _TEST_PATH,
    )

    expect(
        [record["shard_index"] for record in records] == list(range(6))
        and scope["fixture_shards"] == list(range(6))
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
        and {row["name"]: row["sha256"] for row in shard_05["fixtures"]} == _EXPECTED_FIXTURES
        and shard_summary["source_commit"] == shard_05_record["source_commit"]
        and shard_summary["report"]["compressed_sha256"] == hashlib.sha256(shard_05_bytes).hexdigest()
        and shard_summary["report"]["uncompressed_sha256"]
        == hashlib.sha256(gzip.decompress(shard_05_bytes)).hexdigest()
        and shard_05_report["summary"]["expected_tool_runs"] == _EXPECTED_SHARD_ANALYZER_ROWS
        and shard_05_report["summary"]["completed_tool_runs"] == _EXPECTED_SHARD_COMPLETED_ROWS
        and shard_05_report["summary"]["unavailable_tool_runs"] == _EXPECTED_SHARD_UNAVAILABLE_ROWS
        and shard_05_report["tool_summary"]["binary-ninja"]["unavailable"] == _EXPECTED_ROWS_PER_TOOL
        and "binary-ninja" in shard_05_report["summary"]["tools_without_full_completion"]
        and "binary-ninja" not in blocker["tools_without_full_completion"]
        and all(row["tool"] != "binary-ninja" for row in blocker["incomplete_tool_coverage"])
        and blocker["unavailable_tool_runs_by_tool"] == {"triton": _EXPECTED_ROWS_PER_TOOL}
        and aggregate["release_gate"]["all_named_adversarial_analyzers"] == "open"
        and aggregate["release_gate"]["optional_analyzers"] == ["binary-ninja"]
        and aggregate["release_gate"]["required_analyzers_unavailable"] == ["triton"]
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and all(path in criterion["evidence"] for path in evidence_paths)
    )
