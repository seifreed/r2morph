"""Pin two current-main repository-only analyzer shards and their limits."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-01-2026-11-26-summary.json"
_SHARD_00 = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-00-2026-11-26-14e8e0.json.gz"
_SHARD_01 = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-01-2026-11-26-45a58d.json.gz"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_01_45a58d.py"
_FIXTURES = {
    "elf_blockswap_x86_64": "618a267134029c141bd916248100350c9e2402b655c1448451c16fbc7e64c52e",
    "elf_cff_flagdead_x86_64": "25c25a65e9ae2581c3ebc9091c969cf7e1d4232ce325c0d3b343303e22fb13e0",
    "elf_vm_engarithimm_x86_64": "66913c6141fd7999f2f504d9de222aa0bc108a35a88074073b0d3b2227b1209a",
    "elf_vm_flagsynth_x86_64": "2acc5497c7262a204bf2209b273859c7a1be22b5ae2bc3e4f609e1152617000f",
    "elf_vm_fppackedidxnb_x86_64": "a5b98d15463806174fdf87a6ac74ada040ac46690d2dfd0bbbbce4be6a7d63c7",
    "elf_vm_fppackedmem_x86_64": "6abe22f72dae4fe7fc64786a9877cca36ae6e6475a8629b0094fe7662dca1bdc",
    "elf_vm_movidxnb_x86_64": "7bcecfbd2888d7198ed6822f68e14693bc70911bfebfc1ee8a687fe374335047",
    "elf_vm_movq_x86_64": "0afab0583612312c1b669fae39b8ac0bf5c08e3e729d8e83c5442e67e551ab88",
    "elf_vm_shift_x86_64": "e69081768bdeabbbd59cd7611c6780857b20601969c0aa9d66ec50aefcf1cc29",
    "elf_vm_shiftmicroop_x86_64": "1a7b31b591a2fd82a6c53b792e409a1ebf7af959ca2e5bd62218c6e6a8cfe0a8",
    "elf_vm_word16_x86_64": "35b7b1e2eafc74fa66de8b8317a9a6c1c906ba40a43148353d6bb6d334fd95cc",
    "elf_x86_64": "7b2dd51db978d08f362c2b7a0b6062521340207faf1955407361ae3a3268f50a",
}
_SOURCE_COMMITS = {
    "14e8e052540d7df6daa47e532fd48ac2d8fbc3a6",
    "45a58d95ebed7c95d12c642e86fc07f415788137",
}
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_PASS_RUNS = 264
_EXPECTED_TOOL_ROWS = 2_376
_COMPLETED_ROWS = 1_848
_UNAVAILABLE_ROWS = 528
_SHARD_COUNT = 32
_SHARD_FIXTURE_COUNT = 6
_SHARD_PASS_RUNS = 132
_PASS_COUNT = 22


def test_two_repository_shards_bind_all_fixtures_analyzer_rows_and_gaps() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    observed_fixture_hashes = {
        fixture["name"]: hashlib.sha256((_ROOT / fixture["path"]).read_bytes()).hexdigest()
        for fixture in scope["fixtures"]
    }
    reports = []
    for path, shard_index in ((_SHARD_00, 0), (_SHARD_01, 1)):
        compressed = path.read_bytes()
        raw = json.loads(gzip.decompress(compressed))
        record = next(shard for shard in summary["shards"] if shard["shard_index"] == shard_index)
        reports.append(raw)
        expect(
            raw["fixture_shard"] == {"count": _SHARD_COUNT, "index": shard_index}
            and record["raw_sha256"] == hashlib.sha256(compressed).hexdigest()
            and record["raw_path"] == path.relative_to(_ROOT).as_posix()
            and raw["sample_count"] == _SHARD_FIXTURE_COUNT
            and raw["summary"]["expected_pass_runs"] == _SHARD_PASS_RUNS
            and raw["summary"]["missing_pass_runs"] == raw["summary"]["missing_tool_runs"] == 0
        )

    raw_fixture_names = [sample["original"] for report in reports for sample in report["samples"]]
    expect(
        summary["source_commits"]
        == [
            "14e8e052540d7df6daa47e532fd48ac2d8fbc3a6",
            "45a58d95ebed7c95d12c642e86fc07f415788137",
        ]
        and set(summary["source_commits"]) == _SOURCE_COMMITS
        and summary["production_source_identical"]
        and summary["production_source_tree_oids"]
        == {
            "r2morph": "54b5c7eb2cdcf56a684757f0147a539dec05ab87",
            "scripts": "bd7fda8c7353e5dd43dcc1ef66e78fd55655f317",
        }
        and observed_fixture_hashes == _FIXTURES
        and set(raw_fixture_names) == set(_FIXTURES)
        and len(raw_fixture_names) == len(set(raw_fixture_names))
        and scope["fixture_count"] == len(_FIXTURES)
        and scope["pass_count"] == len(reports[0]["pass_names"]) == _PASS_COUNT
        and scope["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and scope["expected_tool_rows"] == _EXPECTED_TOOL_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and set(scope["completed_tool_runs_by_tool"]) | set(scope["unavailable_tool_runs_by_tool"]) == _EXPECTED_TOOLS
        and all(
            scope["completed_tool_runs_by_tool"][tool] == _EXPECTED_PASS_RUNS
            for tool in ("angr", "custom", "ghidra", "ida-pro", "objdump", "radare2", "unicorn")
        )
        and scope["completed_tool_runs_by_tool"]["binary-ninja"] == 0
        and scope["completed_tool_runs_by_tool"]["triton"] == 0
        and scope["unavailable_tool_runs_by_tool"]["binary-ninja"] == _EXPECTED_PASS_RUNS
        and scope["unavailable_tool_runs_by_tool"]["triton"] == _EXPECTED_PASS_RUNS
        and set(scope["pass_names"]) == set(reports[0]["pass_names"]) == set(reports[1]["pass_names"])
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and _SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _SHARD_00.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _SHARD_01.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _TEST_PATH in criterion["evidence"]
        and summary["limits"]
    )
