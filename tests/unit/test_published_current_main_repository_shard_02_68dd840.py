"""Pin current-main repository-only adversarial analyzer shard 2."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-02-2026-11-26-68dd840-summary.json"
_SHARD = _ROOT / "docs/protection-adversarial-local-current-main-repository-shard-02-2026-11-26-68dd840.json.gz"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shard_02_68dd840.py"
_SOURCE_COMMIT = "68dd840a1ef117cae24289514976cbee4d8ef8a2"
_EXPECTED_FIXTURES = {
    "elf_cff_flaglive_x86_64": "bf087f7df00fbe6b25b5e66d8fe5803a77d14f7117f6b9e9151b691692f102b2",
    "elf_vm_fparith_x86_64": "8edcfe42d2d73fb92cd39912335e62799e11f53fd1dcfb62f39f69f2655ba105",
    "elf_vm_fppackedrip_x86_64": "1ba8771a33350117f53afb2a96a83e50cdf6c8956de30f00b53e48bc6e931f70",
    "elf_vm_movtorsp_x86_64": "0c53c8502dcdb6b36289eeca7452259fba022c11a01cb2312bb563d947c47d67",
    "elf_vm_shiftreg_x86_64": "71fc7fe9cacf0f78f1497b9e5eb4a6293e1916bcd55a7c0a053e1467a42bf9d6",
}
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_FIXTURE_COUNT = 5
_EXPECTED_PASS_COUNT = 22
_EXPECTED_ROWS_PER_TOOL = 110
_EXPECTED_TOOL_ROWS = 990
_COMPLETED_TOOL_ROWS = 770
_UNAVAILABLE_TOOL_ROWS = 220
_SHA256_HEX_LENGTH = 64


def test_current_main_repository_shard_02_is_hash_bound_and_reports_analyzer_gaps() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    compressed = _SHARD.read_bytes()
    report_bytes = gzip.decompress(compressed)
    report = json.loads(report_bytes)
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["fixture_shard"] == {"count": 32, "index": 2}
        and summary["report"]["compressed_sha256"] == hashlib.sha256(compressed).hexdigest()
        and summary["report"]["uncompressed_sha256"] == hashlib.sha256(report_bytes).hexdigest()
        and report["fixture_shard"] == {"count": 32, "index": 2}
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
