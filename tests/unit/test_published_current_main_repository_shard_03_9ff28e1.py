"""Pin current-main repository-only adversarial analyzer shard 3."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-03-2026-11-26-9ff28e1-summary.json"
_SHARD = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-03-2026-11-26-9ff28e1.json.gz"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shard_03_9ff28e1.py"
_SOURCE_COMMIT = "9ff28e1ece39824f19b8b2dd9eca60588b517c8f"
_EXPECTED_FIXTURES = {
    "elf_constant_unfold_x86_64": "4fa152b5b323712cb4966b4c13e287f46381fd790611d8504eafd0f09a656a58",
    "elf_vm_fparithidx_x86_64": "bf76d268c07050217809874b8c2ffcc24108dd9b7592de26d01342526c583bdd",
    "elf_vm_fpriprel_x86_64": "b193f4699bfa000c7a7747396d4d4644c83a6dee1448b940e8250f8c0fc02468",
    "elf_vm_movx_x86_64": "959ab68618e6f5efcdac58f34c2b65f713707c892c368b05dd8939c5aeb08038",
    "elf_vm_simdextra_x86_64": "e759c52bab03cc43b7239365631a918aab32815ae1d3f6b66c1984cb6391cc0d",
}
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_FIXTURE_COUNT = 5
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS_PER_TOOL = 110
_EXPECTED_TOOL_ROWS = 990
_COMPLETED_TOOL_ROWS = 770
_UNAVAILABLE_TOOL_ROWS = 220
_SHA256_HEX_LENGTH = 64


def test_current_main_repository_shard_03_is_hash_bound_and_reports_analyzer_gaps() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    compressed = _SHARD.read_bytes()
    report_bytes = gzip.decompress(compressed)
    report = json.loads(report_bytes)
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_tree_oids"]
        == {
            "r2morph": "54b5c7eb2cdcf56a684757f0147a539dec05ab87",
            "scripts": "f2dddc6284047ddb86f955b601d9a4c0dc4f4ffa",
            "fixtures/dataset": "4599b46090109de0b42c58d034a8eb3f1f321512",
        }
        and summary["fixture_shard"] == {"count": 32, "index": 3}
        and summary["report"]["compressed_sha256"] == hashlib.sha256(compressed).hexdigest()
        and summary["report"]["uncompressed_sha256"] == hashlib.sha256(report_bytes).hexdigest()
        and report["fixture_shard"] == {"count": 32, "index": 3}
        and report["sample_count"] == _EXPECTED_FIXTURE_COUNT
        and len(report["pass_names"]) == _EXPECTED_PASS_COUNT
    )

    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in report["samples"]
    }
    expect(
        fixture_hashes == _EXPECTED_FIXTURES
        and {fixture["name"]: fixture["sha256"] for fixture in scope["fixtures"]} == _EXPECTED_FIXTURES
        and all(
            sample["original_sha256"] == _EXPECTED_FIXTURES[sample["original"]]
            and len(sample["passes"]) == _EXPECTED_PASS_COUNT
            and all(len(row["protected_sha256"]) == _SHA256_HEX_LENGTH for row in sample["passes"])
            for sample in report["samples"]
        )
    )

    tool_summary = report["tool_summary"]
    expect(
        set(tool_summary) == _EXPECTED_TOOLS
        and scope["expected_pass_runs"] == _EXPECTED_ROWS_PER_TOOL
        and scope["expected_tool_rows"] == _EXPECTED_TOOL_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_TOOL_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_TOOL_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_ROWS_PER_TOOL
        and scope["completed_tool_runs_by_tool"]["ghidra"] == _EXPECTED_ROWS_PER_TOOL
        and scope["unavailable_tool_runs_by_tool"]["triton"] == _EXPECTED_ROWS_PER_TOOL
        and scope["unavailable_tool_runs_by_tool"]["binary-ninja"] == _EXPECTED_ROWS_PER_TOOL
        and tool_summary["ida-pro"]["errors"] == tool_summary["ghidra"]["errors"] == 0
        and tool_summary["ida-pro"]["completed"] == tool_summary["ghidra"]["completed"] == _EXPECTED_ROWS_PER_TOOL
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and "triton" in criterion["required_analyzers"]
        and _SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _SHARD.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _TEST_PATH in criterion["evidence"]
        and summary["limits"]
    )
