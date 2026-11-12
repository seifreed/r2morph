import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-2867d63b-shard-00.json"
_FIXTURES = {
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
_DECLARED_PASS_COUNT = 22
_NON_APPLIED_PASS_COUNT = 17
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
_AVAILABLE_TOOLS = _EXPECTED_TOOLS - {"binary-ninja", "triton"}
_ANALYST_PATH_MARKERS = (
    "/Users/",
    "/Applications/",
    "/private/",
    f"{PurePosixPath('/', 'tmp').as_posix()}/",
    "/home/",
)


def test_host_adversarial_shard_zero_covers_all_passes_on_its_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 0}
        and report["sample_count"] == len(_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _FIXTURES
        and len(report["pass_names"]) == _DECLARED_PASS_COUNT
        and all(len(sample["passes"]) == len(report["pass_names"]) for sample in report["samples"])
    )


def test_host_adversarial_shard_zero_virtualizes_every_fixture_without_errors() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["pass_summary"]["CodeVirtualization"]["applied"] == len(_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
        and report["pass_summary"]["CodeVirtualization"]["errors"] == 0
    )


def test_host_adversarial_shard_zero_completes_every_available_analyzer_slot() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = report["summary"]
    expected_runs_per_tool = len(_FIXTURES) * len(report["pass_names"])

    expect(
        summary["completed_tool_runs_by_tool"] == {tool: expected_runs_per_tool for tool in _AVAILABLE_TOOLS}
        and summary["completed_tool_runs"] == expected_runs_per_tool * len(_AVAILABLE_TOOLS)
        and summary["expected_tool_runs"] == expected_runs_per_tool * len(_EXPECTED_TOOLS)
        and summary["error_tool_runs"] == 0
    )


def test_host_adversarial_shard_zero_records_unavailable_tools_and_noop_scope() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = report["summary"]
    expected_runs_per_tool = len(_FIXTURES) * _DECLARED_PASS_COUNT

    expect(
        summary["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": expected_runs_per_tool},
            "triton": {"module 'triton' is unavailable": expected_runs_per_tool},
        }
        and len(summary["adversarial_evidence_blockers"]["passes_without_applied_runs"]) == _NON_APPLIED_PASS_COUNT
    )


def test_host_adversarial_shard_zero_does_not_publish_analyst_paths() -> None:
    serialized_report = _REPORT.read_text(encoding="utf-8")

    expect(not any(marker in serialized_report for marker in _ANALYST_PATH_MARKERS))
