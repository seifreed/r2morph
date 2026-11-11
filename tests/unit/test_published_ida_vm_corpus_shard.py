"""Regression checks for the pinned IDA/Ghidra VM corpus shard."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-ida-codevirtualization-shard-2026-11-11-92265ab8.json"
_EXPECTED_FIXTURES = {
    "elf_switch_pie_x86_64",
    "elf_vm_addflaglive_x86_64",
    "elf_vm_boolflaglive_x86_64",
    "elf_vm_call_stack_args_x86_64",
    "elf_vm_cmov_x86_64",
    "elf_vm_lea32_x86_64",
    "elf_vm_prologue_x86_64",
    "elf_vm_run_movxfallback_x86_64",
    "elf_vm_simdwide_x86_64",
    "elf_vm_vpmuldq_x86_64",
}


def test_vm_corpus_shard_covers_expected_dataset_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    samples = report["samples"]

    expect(
        report["fixture_shard"] == {"count": 16, "index": 0}
        and report["sample_count"] == len(_EXPECTED_FIXTURES)
        and {sample["original"] for sample in samples} == _EXPECTED_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and all(
            len(sample["passes"]) == 1
            and sample["passes"][0]["status"] == "applied"
            and sample["passes"][0]["unsupported_functions"] == 0
            for sample in samples
        )
    )


def test_vm_corpus_shard_completed_ida_ghidra_and_unicorn_pairs() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            all(
                tool_row["status"] == "completed"
                and tool_row["original"]["decompiler_status"] == "completed"
                and tool_row["protected"]["decompiler_status"] == "completed"
                for tool_row in sample["tools"]
                if tool_row["tool"] in {"ida-pro", "ghidra"}
            )
            and next(
                tool_row["original"]["exit_code"] == tool_row["protected"]["exit_code"]
                for tool_row in sample["tools"]
                if tool_row["tool"] == "unicorn"
            )
            for sample in report["samples"]
        )
        and all(
            report["tool_summary"][tool]["completed"] == report["sample_count"]
            for tool in ("ida-pro", "ghidra", "unicorn")
        )
    )


def test_vm_corpus_shard_keeps_unavailable_analyzers_explicit() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = report["summary"]

    expect(
        summary["expected_tool_runs"] == report["sample_count"] * summary["expected_tool_count"]
        and summary["completed_tool_runs"] == summary["expected_tool_runs"] - summary["unavailable_tool_runs"]
        and summary["unavailable_tools"] == ["angr", "binary-ninja", "triton"]
        and summary["error_tool_runs"] == 0
    )
