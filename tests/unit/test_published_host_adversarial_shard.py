"""Regression checks for the published host analyzer shard."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-52dfc2ea.json"
_NEXT_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-b8d112a7-shard-01.json"
_THIRD_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json"
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
_NEXT_SHARD_FIXTURES = {
    "elf_vm_arith_x86_64",
    "elf_vm_boolflagdead_x86_64",
    "elf_vm_flagsynth_x86_64",
    "elf_vm_fparith_x86_64",
    "elf_vm_leaidxnb_x86_64",
    "elf_vm_mcall_x86_64",
    "elf_vm_pie_x86_64",
    "elf_vm_shift_x86_64",
    "elf_vm_syscall_x86_64",
    "elf_vm_thread_xchg_x86_64",
    "elf_vm_varargs_x86_64",
}
_NEXT_SHARD_COMPLETED_TOOLS = {"angr", "custom", "ghidra", "ida-pro", "objdump", "radare2", "unicorn"}
_THIRD_SHARD_FIXTURES = {
    "elf_cff_flaglive_x86_64",
    "elf_multiret_jccdiamond_x86_64",
    "elf_vm_fpenginearith_x86_64",
    "elf_vm_fpenginearithrip_x86_64",
    "elf_vm_movtorsp_x86_64",
    "elf_vm_packedmemextra_x86_64",
    "elf_vm_run_memfallback_x86_64",
    "elf_vm_run_riprelfallback_x86_64",
    "elf_vm_vex128_integer_x86_64",
    "elf_vm_vex128_phaddd_x86_64",
}
_THIRD_SHARD_COMPLETED_TOOLS = {"angr", "custom", "ghidra", "ida-pro", "objdump", "radare2"}
_THIRD_SHARD_EXPECTED_TOOLS = _THIRD_SHARD_COMPLETED_TOOLS | {"binary-ninja", "triton", "unicorn"}
_THIRD_SHARD_COMPLETED_RUNS = {
    **{tool: len(_THIRD_SHARD_FIXTURES) for tool in _THIRD_SHARD_COMPLETED_TOOLS},
    "unicorn": len(_THIRD_SHARD_FIXTURES) - 1,
}
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


def test_next_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_NEXT_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 1}
        and report["sample_count"] == len(_NEXT_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _NEXT_SHARD_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_NEXT_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_next_host_adversarial_shard_completes_seven_analyzers() -> None:
    report = json.loads(_NEXT_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: report["sample_count"] for tool in _NEXT_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_NEXT_SHARD_COMPLETED_TOOLS) * report["sample_count"]
        and report["summary"]["error_tool_runs"] == 0
    )


def test_next_host_adversarial_shard_records_only_unavailable_optional_analyzers() -> None:
    report = json.loads(_NEXT_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
        and report["summary"]["unavailable_tool_runs"] == 2 * report["sample_count"]
    )


def test_next_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _NEXT_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_third_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_THIRD_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 2}
        and report["sample_count"] == len(_THIRD_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _THIRD_SHARD_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_THIRD_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_third_host_adversarial_shard_completes_available_analyzer_pairs() -> None:
    report = json.loads(_THIRD_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"] == _THIRD_SHARD_COMPLETED_RUNS
        and report["summary"]["completed_tool_runs"] == sum(_THIRD_SHARD_COMPLETED_RUNS.values())
        and report["summary"]["expected_tool_runs"] == len(_THIRD_SHARD_FIXTURES) * len(_THIRD_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_third_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_THIRD_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
            "unicorn": {"the installed x86 emulator does not support an instruction in this fixture": 1},
        }
    )


def test_third_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _THIRD_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))
