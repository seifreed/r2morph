import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

"""Pinned evidence contracts for published host analyzer shards."""

_ROOT = Path(__file__).resolve().parents[2]
_THIRD_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json"
_FOURTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-0208d79e-shard-03.json"
_FIFTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-ebe50ae2-shard-04.json"
_SIXTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-811ab859-shard-05.json"
_SEVENTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-50496238-shard-06.json"
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
_FOURTH_SHARD_FIXTURES = {
    "elf_vm_cmp8_x86_64",
    "elf_vm_dynamic_x86_64",
    "elf_vm_fpcmp_x86_64",
    "elf_vm_fpengineidxnb_x86_64",
    "elf_vm_fpenginerip_x86_64",
    "elf_vm_leaidx_x86_64",
    "elf_vm_movabs_x86_64",
    "elf_vm_run_movxidxfallback_x86_64",
    "elf_vm_vex128_shift_x86_64",
    "elf_vm_vpmuludq_x86_64",
}
_FOURTH_SHARD_COMPLETED_TOOLS = {"angr", "custom", "ghidra", "ida-pro", "objdump", "radare2"}
_FOURTH_SHARD_COMPLETED_RUNS = {
    **{tool: len(_FOURTH_SHARD_FIXTURES) for tool in _FOURTH_SHARD_COMPLETED_TOOLS},
    "unicorn": len(_FOURTH_SHARD_FIXTURES) - 1,
}
_FOURTH_SHARD_EXPECTED_TOOLS = _FOURTH_SHARD_COMPLETED_TOOLS | {"binary-ninja", "triton", "unicorn"}
_FIFTH_SHARD_FIXTURES = {
    "elf_vm_cmpsynth_x86_64",
    "elf_vm_fpindexed_x86_64",
    "elf_vm_gs_tls_x86_64",
    "elf_vm_idxcall_x86_64",
    "elf_vm_incall_x86_64",
    "elf_vm_memops_x86_64",
    "elf_vm_memwidth_x86_64",
    "elf_vm_movx_x86_64",
    "elf_vm_vex256_unpack_x86_64",
    "elf_vm_vex_word_shuffle_x86_64",
}
_FIFTH_SHARD_EXPECTED_TOOLS = {
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
_FIFTH_SHARD_COMPLETED_RUNS = {
    "angr": len(_FIFTH_SHARD_FIXTURES),
    "custom": len(_FIFTH_SHARD_FIXTURES),
    "ghidra": len(_FIFTH_SHARD_FIXTURES),
    "ida-pro": len(_FIFTH_SHARD_FIXTURES),
    "objdump": len(_FIFTH_SHARD_FIXTURES),
    "radare2": len(_FIFTH_SHARD_FIXTURES),
    "unicorn": len(_FIFTH_SHARD_FIXTURES) - 2,
}
_SIXTH_SHARD_FIXTURES = {
    "elf_vm_div_x86_64",
    "elf_vm_fparithriprel_x86_64",
    "elf_vm_fpengineconvert32_x86_64",
    "elf_vm_fppackedmem_x86_64",
    "elf_vm_gs_tlsidxnb_x86_64",
    "elf_vm_interp_stack_x86_64",
    "elf_vm_memdst_x86_64",
    "elf_vm_movd_x86_64",
    "elf_vm_pushimm_x86_64",
    "elf_vm_pushpop16_x86_64",
}
_SIXTH_SHARD_EXPECTED_TOOLS = {
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
_SIXTH_SHARD_COMPLETED_TOOLS = _SIXTH_SHARD_EXPECTED_TOOLS - {"binary-ninja", "triton"}
_SEVENTH_SHARD_FIXTURES = {
    "elf_nop_x86_64",
    "elf_vm_fparithidx_x86_64",
    "elf_vm_fppacked_x86_64",
    "elf_vm_imul3_x86_64",
    "elf_vm_movxidx_x86_64",
    "elf_vm_pushmem_x86_64",
    "elf_vm_run_riprelarithfallback_x86_64",
    "elf_vm_simdmove_x86_64",
    "elf_vm_subflagdead_x86_64",
    "elf_vm_vex128_horizontal_x86_64",
}
_SEVENTH_SHARD_EXPECTED_TOOLS = {
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
_SEVENTH_SHARD_COMPLETED_TOOLS = _SEVENTH_SHARD_EXPECTED_TOOLS - {"binary-ninja", "triton"}
_EIGHTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-95ada1f8-shard-07.json"
_EIGHTH_SHARD_FIXTURES = {
    "elf_blockswap_x86_64",
    "elf_constant_unfold_x86_64",
    "elf_vm_fpconvert_x86_64",
    "elf_vm_fpengineidx_x86_64",
    "elf_vm_fppacked_compare16_x86_64",
    "elf_vm_incdec8_x86_64",
    "elf_vm_multiexit_x86_64",
    "elf_vm_popmem_x86_64",
    "elf_vm_run_idxfallback_x86_64",
    "elf_vm_vex128_unpack_x86_64",
    "elf_x86_64",
}
_EIGHTH_SHARD_EXPECTED_TOOLS = {
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
_EIGHTH_SHARD_COMPLETED_TOOLS = _EIGHTH_SHARD_EXPECTED_TOOLS - {"binary-ninja", "triton"}
_NINTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-a508ec2b-shard-08.json"
_NINTH_SHARD_FIXTURES = {
    "elf_vm_engarithimm_x86_64",
    "elf_vm_fpmove_x86_64",
    "elf_vm_fppackedariprip_x86_64",
    "elf_vm_incdec_x86_64",
    "elf_vm_interp_reg_x86_64",
    "elf_vm_movxreg_x86_64",
    "elf_vm_opmem_x86_64",
    "elf_vm_run_leafallback_x86_64",
    "elf_vm_tls_widths_x86_64",
    "elf_vm_vex128_scalar_x86_64",
}
_NINTH_SHARD_EXPECTED_TOOLS = {
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
_NINTH_SHARD_COMPLETED_TOOLS = _NINTH_SHARD_EXPECTED_TOOLS - {"binary-ninja", "triton"}
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


def test_fourth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_FOURTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 3}
        and report["sample_count"] == len(_FOURTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _FOURTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_FOURTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_fourth_host_adversarial_shard_completes_available_analyzers() -> None:
    report = json.loads(_FOURTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"] == _FOURTH_SHARD_COMPLETED_RUNS
        and report["summary"]["completed_tool_runs"] == sum(_FOURTH_SHARD_COMPLETED_RUNS.values())
        and report["summary"]["expected_tool_runs"] == len(_FOURTH_SHARD_FIXTURES) * len(_FOURTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_fourth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_FOURTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
            "unicorn": {"the installed x86 emulator does not support an instruction in this fixture": 1},
        }
    )


def test_fourth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _FOURTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_fifth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_FIFTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 4}
        and report["sample_count"] == len(_FIFTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _FIFTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_FIFTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_fifth_host_adversarial_shard_completes_available_analyzers() -> None:
    report = json.loads(_FIFTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"] == _FIFTH_SHARD_COMPLETED_RUNS
        and report["summary"]["completed_tool_runs"] == sum(_FIFTH_SHARD_COMPLETED_RUNS.values())
        and report["summary"]["expected_tool_runs"] == len(_FIFTH_SHARD_FIXTURES) * len(_FIFTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_fifth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_FIFTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
            "unicorn": {"the installed x86 emulator does not support an instruction in this fixture": 2},
        }
    )


def test_fifth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _FIFTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_sixth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_SIXTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 5}
        and report["sample_count"] == len(_SIXTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _SIXTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_SIXTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_sixth_host_adversarial_shard_completes_all_available_analyzers() -> None:
    report = json.loads(_SIXTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_SIXTH_SHARD_FIXTURES) for tool in _SIXTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_SIXTH_SHARD_FIXTURES) * len(_SIXTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"] == len(_SIXTH_SHARD_FIXTURES) * len(_SIXTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_sixth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_SIXTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_sixth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _SIXTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_seventh_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_SEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 6}
        and report["sample_count"] == len(_SEVENTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _SEVENTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_SEVENTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_seventh_host_adversarial_shard_completes_all_available_analyzers() -> None:
    report = json.loads(_SEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_SEVENTH_SHARD_FIXTURES) for tool in _SEVENTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"]
        == len(_SEVENTH_SHARD_FIXTURES) * len(_SEVENTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"] == len(_SEVENTH_SHARD_FIXTURES) * len(_SEVENTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_seventh_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_SEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_seventh_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _SEVENTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_eighth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_EIGHTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 7}
        and report["sample_count"] == len(_EIGHTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _EIGHTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_EIGHTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_eighth_host_adversarial_shard_completes_all_available_analyzers() -> None:
    report = json.loads(_EIGHTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_EIGHTH_SHARD_FIXTURES) for tool in _EIGHTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_EIGHTH_SHARD_FIXTURES) * len(_EIGHTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"] == len(_EIGHTH_SHARD_FIXTURES) * len(_EIGHTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_eighth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_EIGHTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_eighth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _EIGHTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_ninth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_NINTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 8}
        and report["sample_count"] == len(_NINTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _NINTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_NINTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_ninth_host_adversarial_shard_completes_all_available_analyzers() -> None:
    report = json.loads(_NINTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_NINTH_SHARD_FIXTURES) for tool in _NINTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_NINTH_SHARD_FIXTURES) * len(_NINTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"] == len(_NINTH_SHARD_FIXTURES) * len(_NINTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_ninth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_NINTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_ninth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _NINTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))
