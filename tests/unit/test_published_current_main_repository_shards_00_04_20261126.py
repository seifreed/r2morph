"""Pin the combined current-main evidence for repository shards 0 through 4."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-04-2026-11-26-summary.json"
_SHARD_04_SUMMARY = (
    _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-04-2026-11-26-71549123-summary.json"
)
_SHARD_04_RAW = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-04-2026-11-26-71549123.json.gz"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_04_20261126.py"
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_FIXTURES = {
    "elf_flag_live_x86_64": "c687592c788ca5e1a2875fdfaf0e705579bff1a20dc54d3e6df88b4fcc3159e1",
    "elf_vm_fparithidxnb_x86_64": "cfc4bfbae001954a37de8ad434c2f37122b592c104b90c015785836b17cc5b43",
    "elf_vm_global_x86_64": "59e2a926c569127ea0e58d5b8dcf85562bfa05b45d10f0260be147e253799072",
    "elf_vm_movxidx_x86_64": "06ff91feff24cdb11723827fd8eb92ed90781af836b7d43355d59603831ff696",
    "elf_vm_simdint_x86_64": "0ea456c94f2fa6b58758a156aab2628c9ba91f5ad02e9f837fb4c60c6e67952f",
}
_EXPECTED_FIXTURE_COUNT = 27
_EXPECTED_PASS_COUNT = 22
_EXPECTED_PASS_ROWS = 594
_EXPECTED_ANALYZER_ROWS = 5_346
_EXPECTED_COMPLETED_ROWS = 4_158
_EXPECTED_UNAVAILABLE_ROWS = 1_188
_EXPECTED_SHARD_04_INDEX = 4
_SHA256_HEX_LENGTH = 64
_EXPECTED_TREE_OIDS = {
    "r2morph": "54b5c7eb2cdcf56a684757f0147a539dec05ab87",
    "fixtures/dataset": "4599b46090109de0b42c58d034a8eb3f1f321512",
}


def _read_shard(root: Path, record: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    compressed = (root / record["raw_path"]).read_bytes()
    report = json.loads(gzip.decompress(compressed))
    expect(
        hashlib.sha256(compressed).hexdigest() == record["raw_sha256"]
        and report["fixture_shard"] == {"count": 32, "index": record["shard_index"]}
        and report["summary"]["missing_pass_runs"] == report["summary"]["missing_tool_runs"] == 0
        and report["summary"]["error_tool_runs"] == 0
    )
    return compressed, report


def test_five_repository_shards_have_complete_hash_bound_aggregate_evidence() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    records = summary["shards"]
    loaded = [_read_shard(_ROOT, record) for record in records]
    reports = [report for _compressed, report in loaded]

    shard_04_record = next(record for record in records if record["shard_index"] == _EXPECTED_SHARD_04_INDEX)
    shard_04_summary = json.loads((_ROOT / shard_04_record["summary_path"]).read_text(encoding="utf-8"))
    shard_04_bytes, shard_04_report = loaded[4]
    shard_04 = shard_04_summary["scope"]
    current_fixtures = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in shard_04_report["samples"]
    }

    completed_by_tool = {
        tool: sum(report["tool_summary"][tool]["completed"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    unavailable_by_tool = {
        tool: sum(report["tool_summary"][tool]["unavailable"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    all_fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for report in reports
        for sample in report["samples"]
    }
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(
        summary["production_source_tree_oids"] == _EXPECTED_TREE_OIDS
        and summary["benchmark_script_tree_oids"]
        == {
            "shards_00_01": "bd7fda8c7353e5dd43dcc1ef66e78fd55655f317",
            "shards_02_03": "f2dddc6284047ddb86f955b601d9a4c0dc4f4ffa",
            "shard_04": "f2dddc6284047ddb86f955b601d9a4c0dc4f4ffa",
        }
        and [record["shard_index"] for record in records] == [0, 1, 2, 3, 4]
        and scope["fixture_shards"] == [0, 1, 2, 3, 4]
        and scope["fixture_count"] == len(all_fixture_hashes) == _EXPECTED_FIXTURE_COUNT
        and all_fixture_hashes == {fixture["name"]: fixture["sha256"] for fixture in scope["fixtures"]}
        and all(len(report["pass_names"]) == _EXPECTED_PASS_COUNT for report in reports)
        and all(report["pass_names"] == reports[0]["pass_names"] for report in reports)
        and scope["expected_pass_runs"] == _EXPECTED_PASS_ROWS
        and scope["expected_tool_rows"] == _EXPECTED_ANALYZER_ROWS
        and scope["completed_tool_rows"] == _EXPECTED_COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _EXPECTED_UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"] == completed_by_tool
        and scope["unavailable_tool_runs_by_tool"] == unavailable_by_tool
        and completed_by_tool["ida-pro"] == completed_by_tool["ghidra"] == _EXPECTED_PASS_ROWS
        and unavailable_by_tool["triton"] == unavailable_by_tool["binary-ninja"] == _EXPECTED_PASS_ROWS
        and shard_04_summary["source_commit"] == "71549123e274fe36f471b8793d94043978af9779"
        and shard_04_summary["report"]["compressed_sha256"] == hashlib.sha256(shard_04_bytes).hexdigest()
        and shard_04_summary["report"]["uncompressed_sha256"]
        == hashlib.sha256(gzip.decompress(shard_04_bytes)).hexdigest()
        and current_fixtures == _EXPECTED_FIXTURES
        and {fixture["name"]: fixture["sha256"] for fixture in shard_04["fixtures"]} == _EXPECTED_FIXTURES
        and all(
            sample["original_sha256"] == _EXPECTED_FIXTURES[sample["original"]]
            and len(sample["passes"]) == _EXPECTED_PASS_COUNT
            and all(len(row["protected_sha256"]) == _SHA256_HEX_LENGTH for row in sample["passes"])
            for sample in shard_04_report["samples"]
        )
        and summary["release_gate"]["all_named_adversarial_analyzers"] == "open"
        and "binary-ninja" in summary["release_gate"]["optional_analyzers"]
        and "triton" in summary["release_gate"]["required_analyzers_unavailable"]
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and _SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _SHARD_04_SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _SHARD_04_RAW.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _TEST_PATH in criterion["evidence"]
    )
