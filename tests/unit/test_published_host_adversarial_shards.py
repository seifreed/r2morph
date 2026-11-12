import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

"""Pinned evidence contracts for published host analyzer shards."""

_ROOT = Path(__file__).resolve().parents[2]
_SHA256_HEX_LENGTH = 64
_SIXTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-811ab859-shard-05.json"
_SEVENTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-11-50496238-shard-06.json"
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
_TENTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-c30d1337-shard-09.json"
_TENTH_SHARD_FIXTURES = {
    "elf_jumpchain_x86_64",
    "elf_switch_abs_x86_64",
    "elf_vm_call_callee_saved_x86_64",
    "elf_vm_cmp8imm_x86_64",
    "elf_vm_fpenginearithmem_x86_64",
    "elf_vm_interp_x86_64",
    "elf_vm_movidx_x86_64",
    "elf_vm_setcc_x86_64",
    "elf_vm_thread_cmpxchg_x86_64",
    "elf_vm_thread_mematomicimm_x86_64",
}
_TENTH_SHARD_EXPECTED_TOOLS = {
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
_TENTH_SHARD_COMPLETED_TOOLS = _TENTH_SHARD_EXPECTED_TOOLS - {"binary-ninja", "triton"}
_ELEVENTH_SHARD_REPORT = _ROOT / "docs" / "protection-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json"
_ELEVENTH_SHARD_FIXTURES = {
    "elf_vm_bswap_x86_64",
    "elf_vm_call_x86_64",
    "elf_vm_callflags_stack_x86_64",
    "elf_vm_fpenginemove_x86_64",
    "elf_vm_fppackedaridx_x86_64",
    "elf_vm_fppackedidxnb_x86_64",
    "elf_vm_lea_x86_64",
    "elf_vm_phaddmem_x86_64",
    "elf_vm_redzone_x86_64",
    "elf_vm_simdint_x86_64",
    "elf_vm_unwind_x86_64",
}
_ELEVENTH_SHARD_EXPECTED_TOOLS = {
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
_ELEVENTH_SHARD_COMPLETED_TOOLS = _ELEVENTH_SHARD_EXPECTED_TOOLS - {
    "binary-ninja",
    "ghidra",
    "ida-pro",
    "triton",
}
_IDA_ELEVENTH_SHARD_REPORT = _ROOT / "docs" / "protection-ida-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json"
_ANALYST_PATH_MARKERS = (
    "/Users/",
    "/Applications/",
    "/private/",
    f"{PurePosixPath('/', 'tmp').as_posix()}/",
    "/home/",
)


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


def test_tenth_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_TENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 9}
        and report["sample_count"] == len(_TENTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _TENTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_TENTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_tenth_host_adversarial_shard_completes_all_available_analyzers() -> None:
    report = json.loads(_TENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_TENTH_SHARD_FIXTURES) for tool in _TENTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"] == len(_TENTH_SHARD_FIXTURES) * len(_TENTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"] == len(_TENTH_SHARD_FIXTURES) * len(_TENTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_tenth_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_TENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_tenth_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _TENTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_eleventh_host_adversarial_shard_applies_virtualization_to_new_fixtures() -> None:
    report = json.loads(_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 10}
        and report["sample_count"] == len(_ELEVENTH_SHARD_FIXTURES)
        and {sample["original"] for sample in report["samples"]} == _ELEVENTH_SHARD_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == len(_ELEVENTH_SHARD_FIXTURES)
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
    )


def test_eleventh_host_adversarial_shard_completes_all_locally_available_analyzers() -> None:
    report = json.loads(_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["completed_tool_runs_by_tool"]
        == {tool: len(_ELEVENTH_SHARD_FIXTURES) for tool in _ELEVENTH_SHARD_COMPLETED_TOOLS}
        and report["summary"]["completed_tool_runs"]
        == len(_ELEVENTH_SHARD_FIXTURES) * len(_ELEVENTH_SHARD_COMPLETED_TOOLS)
        and report["summary"]["expected_tool_runs"]
        == len(_ELEVENTH_SHARD_FIXTURES) * len(_ELEVENTH_SHARD_EXPECTED_TOOLS)
        and report["summary"]["error_tool_runs"] == 0
    )


def test_eleventh_host_adversarial_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": report["sample_count"]},
            "ghidra": {"executable 'ghidra' is unavailable": report["sample_count"]},
            "ida-pro": {"executable 'idat' is unavailable": report["sample_count"]},
            "triton": {"module 'triton' is unavailable": report["sample_count"]},
        }
    )


def test_eleventh_host_adversarial_shard_does_not_publish_analyst_paths() -> None:
    report = _ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _ANALYST_PATH_MARKERS))


def test_ida_eleventh_host_shard_matches_adversarial_fixture_pairs() -> None:
    report = json.loads(_IDA_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["source_commit"] == "74a3e18d31a1d6df513f3044140981d082b1a3da"
        and report["scope"]
        == {
            "os": "macOS",
            "format": "ELF",
            "architecture": "x86-64",
            "pass": "CodeVirtualization",
            "fixture_shard": {"index": 10, "count": 16},
            "seed": 20260827,
        }
        and {sample["fixture"] for sample in report["samples"]} == _ELEVENTH_SHARD_FIXTURES
        and report["sample_count"] == len(_ELEVENTH_SHARD_FIXTURES)
    )


def test_ida_eleventh_host_shard_decompiles_every_discovered_function() -> None:
    report = json.loads(_IDA_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]
        == {
            "original_functions": 16,
            "original_decompiled_functions": 16,
            "protected_functions": 28,
            "protected_decompiled_functions": 28,
            "original_decompiler_output_bytes": 1746,
            "protected_decompiler_output_bytes": 8139,
            "original_decompiler_output_lines": 93,
            "protected_decompiler_output_lines": 308,
            "error_count": 0,
        }
        and all(
            sample[side]["function_count"] == sample[side]["decompiled_count"]
            and sample[side]["error_count"] == 0
            and sample[side]["decompiler_output_bytes"] > 0
            and sample[side]["decompiler_output_lines"] > 0
            for sample in report["samples"]
            for side in ("original", "protected")
        )
    )


def test_ida_eleventh_host_shard_pins_binary_hashes_without_host_paths() -> None:
    report = json.loads(_IDA_ELEVENTH_SHARD_REPORT.read_text(encoding="utf-8"))
    serialized_report = json.dumps(report)

    expect(
        all(
            len(sample[hash_name]) == _SHA256_HEX_LENGTH
            for sample in report["samples"]
            for hash_name in ("original_sha256", "protected_sha256")
        )
        and not any(marker in serialized_report for marker in _ANALYST_PATH_MARKERS)
    )
