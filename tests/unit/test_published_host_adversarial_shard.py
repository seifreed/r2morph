"""Regression checks for the published host analyzer shard."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-52dfc2ea.json"
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
_COMPLETED_TOOLS = {"angr", "custom", "ghidra", "ida-pro", "objdump", "radare2", "unicorn"}
_ANALYST_PATH_MARKERS = (
    "/Users/",
    "/Applications/",
    "/private/",
    f"{PurePosixPath('/', 'tmp').as_posix()}/",
    "/home/",
)


def test_host_adversarial_shard_applies_virtualization_to_expected_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 0}
        and report["sample_count"] == len(_EXPECTED_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _EXPECTED_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_EXPECTED_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_host_adversarial_shard_completes_available_analyzer_pairs() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"] == {tool: report["sample_count"] for tool in _COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_COMPLETED_TOOLS) * report["sample_count"]
        and report["summary"]["error_tool_runs"] == 0
    )


def test_host_adversarial_shard_preserves_unavailable_analyzer_reasons() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
        and report["summary"]["unavailable_tool_runs"] == 2 * report["sample_count"]
    )


def test_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))
