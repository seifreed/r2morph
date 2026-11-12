import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-0ab74d02-shard-11.json"
_EXPECTED_PASS_COUNT = 22
_EXPECTED_COMPLETED_TOOL_RUNS = 1518
_EXPECTED_TOOL_RUNS = 1980
_EXPECTED_FIXTURES = {
    "elf_vm_cmpmem_x86_64",
    "elf_vm_fpcmpmem_x86_64",
    "elf_vm_fpenginepacked_x86_64",
    "elf_vm_fppackedidx_x86_64",
    "elf_vm_global_x86_64",
    "elf_vm_icall_x86_64",
    "elf_vm_shiftmicroop_x86_64",
    "elf_vm_simdextra_x86_64",
    "elf_vm_varargs_scalar_x86_64",
    "elf_vm_vex256_packusdw_mem_x86_64",
}
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp').as_posix()}/", "/home/")


def test_twelfth_host_shard_applies_virtualization_to_all_fixtures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 11}
        and report["sample_count"] == len(_EXPECTED_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _EXPECTED_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_EXPECTED_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
        and len(report["pass_names"]) == _EXPECTED_PASS_COUNT
    )


def test_twelfth_host_shard_completes_available_analyzers_without_missing_rows() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = report["summary"]

    expect(
        set(report["tool_summary"]) == _EXPECTED_TOOLS
        and summary["completed_tool_runs"] == _EXPECTED_COMPLETED_TOOL_RUNS
        and summary["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and summary["error_tool_runs"] == 0
        and summary["missing_tool_runs"] == 0
    )


def test_twelfth_host_shard_records_unavailable_tool_reasons() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": 220},
            "triton": {"module 'triton' is unavailable": 220},
            "unicorn": {"the installed x86 emulator does not support an instruction in this fixture": 22},
        }
    )


def test_twelfth_host_shard_does_not_publish_analyst_paths() -> None:
    report = _REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _PATH_MARKERS))
