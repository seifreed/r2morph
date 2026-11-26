"""Pin the current-main repository-only analyzer shard and its limits."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-00-2026-11-26-14e8e0-summary.json"
_RAW = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-00-2026-11-26-14e8e0.json.gz"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shard_00_14e8e0.py"
_SOURCE_COMMIT = "14e8e052540d7df6daa47e532fd48ac2d8fbc3a6"
_RAW_SHA256 = "0d16685c5fd813945a35c5ab146a8814512491d210e6165b85e7c85aae446856"
_FIXTURES = {
    "elf_blockswap_x86_64": "618a267134029c141bd916248100350c9e2402b655c1448451c16fbc7e64c52e",
    "elf_vm_engarithimm_x86_64": "66913c6141fd7999f2f504d9de222aa0bc108a35a88074073b0d3b2227b1209a",
    "elf_vm_fppackedidxnb_x86_64": "a5b98d15463806174fdf87a6ac74ada040ac46690d2dfd0bbbbce4be6a7d63c7",
    "elf_vm_movidxnb_x86_64": "7bcecfbd2888d7198ed6822f68e14693bc70911bfebfc1ee8a687fe374335047",
    "elf_vm_shift_x86_64": "e69081768bdeabbbd59cd7611c6780857b20601969c0aa9d66ec50aefcf1cc29",
    "elf_vm_word16_x86_64": "35b7b1e2eafc74fa66de8b8317a9a6c1c906ba40a43148353d6bb6d334fd95cc",
}
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
_PASS_COUNT = 22
_PASS_RUNS = 132
_TOOL_ROWS = 1_188
_COMPLETED_ROWS = 924
_UNAVAILABLE_ROWS = 264


def test_repository_shard_binds_fixture_hashes_analyzer_rows_and_gaps() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    raw_bytes = _RAW.read_bytes()
    raw = json.loads(gzip.decompress(raw_bytes))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    analyzers = scope["analyzers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]
    observed_fixture_hashes = {
        fixture["name"]: hashlib.sha256((_ROOT / fixture["path"]).read_bytes()).hexdigest()
        for fixture in scope["fixtures"]
    }

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["raw_report"]["sha256"] == hashlib.sha256(raw_bytes).hexdigest() == _RAW_SHA256
        and observed_fixture_hashes == _FIXTURES
        and raw["fixture_shard"] == {"count": 32, "index": 0}
        and scope["fixture_count"] == len(_FIXTURES)
        and scope["pass_count"] == len(raw["pass_names"]) == _PASS_COUNT
        and scope["expected_pass_runs"] == _PASS_RUNS
        and scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["expected_tool_rows"] == _TOOL_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == 0
        and set(analyzers) == _EXPECTED_TOOLS
        and all(analyzer["runs"] == _PASS_RUNS for analyzer in analyzers.values())
        and all(analyzer["errors"] == 0 for analyzer in analyzers.values())
        and analyzers["ida-pro"]["completed"] == analyzers["ghidra"]["completed"] == _PASS_RUNS
        and analyzers["binary-ninja"]["unavailable"] == _PASS_RUNS
        and analyzers["triton"]["unavailable"] == _PASS_RUNS
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and _SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _RAW.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _TEST_PATH in criterion["evidence"]
        and summary["limits"]
    )
