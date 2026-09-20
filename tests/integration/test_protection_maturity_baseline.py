"""Regression coverage for the real protection maturity measurement harness."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from r2morph.adapters.process import run_process
from r2morph.core.binary import Binary
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.short_jump_patching import ShortJumpPatchingPass
from scripts.protection_maturity_baseline import (
    _GENERATED_CORPUS_FAMILY,
    _GENERATED_CORPUS_PROFILES,
    _GENERATED_CORPUS_SOURCES,
    _GENERATED_CPP_CORPUS_FAMILY,
    _GENERATED_CPP_CORPUS_PROFILES,
    _GENERATED_RUNTIME_INPUTS,
    _PASS_TYPES,
    _PREVIEW_BYTES,
    CORPUS_PASS_NAMES,
    EXTENDED_MATURITY_PASS_NAMES,
    _affected_instruction_evidence,
    _ArtifactAccumulator,
    _behavioral_false_positive_metrics,
    _complete_evidence_error,
    _diagnostic_counts,
    _independent_semantic_pair,
    _measure_seed,
    _parse_pass_names,
    _render_multi_pass_result,
    _render_result,
    _run_runtime,
    _runtime_artifacts,
    _runtime_observables_equal,
    _select_fixture_shard,
    _selected_generated_fixture_names,
    _semantic_artifacts,
    _semantic_run_matches,
    _transformation_evidence,
    discover_executables,
    measure_fixture,
    merge_maturity_reports,
    sha256,
)
from tests.conftest import _compile_elf_x86_64_binary
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_arith_x86_64"
_CONSTANT_UNFOLD_FIXTURE = _DATASET / "elf_constant_unfold_x86_64"
_CONTROL_FLOW_FIXTURE = _DATASET / "elf_cff_flagdead_x86_64"
_DEAD_CODE_FIXTURE = _DATASET / "elf_cff_flagdead_x86_64"
_NOP_FIXTURE = _DATASET / "elf_nop_x86_64"
_PIE_FIXTURE = _DATASET / "elf_vm_pie_x86_64"
_VARARGS_FIXTURE = _DATASET / "elf_vm_varargs_x86_64"
_PACKED_INDEXED_FIXTURE = _DATASET / "elf_vm_fppackedidxnb_x86_64"
_VEX_WORD_SHUFFLE_FIXTURE = _DATASET / "elf_vm_vex_word_shuffle_x86_64"
_EXPECTED_PIE_EXIT_CODE = 73
_EXPECTED_PACKED_INDEXED_EXIT_CODE = 6
_EXPECTED_VARARGS_EXIT_CODE = 69
_EXPECTED_DATA_FLOW_EXIT_CODE = 14
_EXPECTED_SHORT_JUMP_EXIT_CODE = 7
_FLAG_LIVE_FIXTURE = _DATASET / "elf_flag_live_x86_64"
_EXPECTED_TOTAL_SIZE_DELTA_BYTES = 20
_EXPECTED_MAX_SIZE_DELTA_BYTES = 25
_EXPECTED_MIN_SIZE_DELTA_BYTES = -5
_EXPECTED_TRANSFORM_DURATION_SECONDS = 0.75
_EXPECTED_STATIC_FUNCTIONS_DELTA = 2
_EXPECTED_STATIC_INSTRUCTIONS_DELTA = 9
_EXPECTED_RUNTIME_COMPLETE_RUNS = 2
_EXPECTED_OUTPUT_SIZE_COMPLETE_RUNS = 2
_EXPECTED_TRANSFORM_DURATION_COMPLETE_RUNS = 2
_EXPECTED_RUNTIME_DURATION_COMPLETE_RUNS = 2
_EXPECTED_STATIC_COMPLETE_RUNS = 2
_EXPECTED_COMPLETE_EVIDENCE_RUNS = 2
_EXPECTED_BEHAVIORAL_VALIDATION_OBSERVATIONS = 2
_EXPECTED_BEHAVIORAL_FALSE_POSITIVE_OBSERVATIONS = 1
_EXPECTED_BEHAVIORAL_FALSE_POSITIVE_RATE = 50.0
_EXPECTED_FULL_COVERAGE_PERCENT = 100.0
_EXPECTED_MULTI_PASS_COUNT = 2
_EXPECTED_CORPUS_PASS_COUNT = len(CORPUS_PASS_NAMES)
_EXPECTED_EXTENDED_PASS_COUNT = len(EXTENDED_MATURITY_PASS_NAMES)
_EXPECTED_GENERATED_CORPUS_SOURCES = (
    "generated_abi",
    "generated_branch",
    "generated_calls",
    "generated_cpp",
    "generated_cpp_exceptions",
    "generated_extended",
    "generated_lookup",
    "generated_memory",
    "generated_pointers",
    "generated_recursive",
    "generated_signals",
    "generated_simd",
    "generated_stack_strings",
    "generated_string",
    "generated_threads",
    "generated_xlat",
)
_EXPECTED_MERGED_GENERATED_FIXTURE_COUNT = 2
_EXPECTED_GENERATED_FIXTURE_COUNT = (len(_EXPECTED_GENERATED_CORPUS_SOURCES) - 2) * len(
    _GENERATED_CORPUS_PROFILES
) + 2 * len(_GENERATED_CPP_CORPUS_PROFILES)
_EXPECTED_MISSING_CORPUS_PASSES = sorted(set(CORPUS_PASS_NAMES) - {"CodeVirtualization", "PatternSubstitution"})
_EXPECTED_MISSING_EXTENDED_PASSES = sorted(EXTENDED_MATURITY_PASS_NAMES)
_EXPECTED_CORPUS_PASS_COVERAGE_PERCENT = 20.0
_EXPECTED_MULTI_PASS_CLASSIFIED_RUNS = 2
_EXPECTED_MULTI_PASS_SEED_RUNS = 2
_EXPECTED_AVERAGE_COVERAGE_PERCENT = 50.0
_EXPECTED_EMPTY_COVERAGE_PERCENT = 0.0
_EXPECTED_CAMPAIGN_OUTPUT_SIZE_DELTA_BYTES = 20
_EXPECTED_CAMPAIGN_TRANSFORM_DURATION_SECONDS = 0.5
_EXPECTED_CAMPAIGN_RUNTIME_DURATION_DELTA_SECONDS = 0.25
_EXPECTED_CAMPAIGN_STATIC_FUNCTIONS_DELTA = 1
_SHORT_JUMP_SOURCE = """
.intel_syntax noprefix
.global _start
.text
_start:
    xor rcx, rcx
    jrcxz done
    .rept 8
    nop
    .endr
done:
    mov edi, 7
    mov eax, 60
    syscall
"""
_DATA_FLOW_SOURCE = """
.global _start
.text
_start:
    mov $7, %edi
    call data_flow_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.type data_flow_probe,@function
data_flow_probe:
    mov %rdi, %rcx
    mov %rdi, %rax
    add $3, %rax
    mov %rax, %rdx
    add $4, %rax
    ret
.size data_flow_probe, .-data_flow_probe
"""
_EXPECTED_INCOMPLETE_COVERAGE = {
    "runtime_observable": ["PatternSubstitution"],
    "output_size": ["PatternSubstitution"],
    "transform_duration": ["PatternSubstitution"],
    "runtime_duration": ["PatternSubstitution"],
    "static_metric": ["PatternSubstitution"],
    "complete_evidence": ["PatternSubstitution"],
}
_EXPECTED_METRIC_RUN_TOTALS = {
    "runtime_observable": 1,
    "output_size": 1,
    "transform_duration": 1,
    "runtime_duration": 1,
    "static_metric": 1,
    "complete_evidence": 1,
}
_EXPECTED_OMISSION_REASONS_BY_PASS = {"PatternSubstitution": {"no eligible function was transformed": 1}}
_EXPECTED_OMISSION_SEVERITIES_BY_PASS = {"PatternSubstitution": {"warning": 1}}
_EXPECTED_CONTINUOUS_EVIDENCE_BLOCKERS = {
    "missing_corpus_passes": _EXPECTED_MISSING_CORPUS_PASSES,
    "metric_missing_runs": _EXPECTED_METRIC_RUN_TOTALS,
    "passes_without_applied_runs": ["PatternSubstitution"],
    "passes_with_incomplete_coverage": _EXPECTED_INCOMPLETE_COVERAGE,
    "passes_with_semantic_failures": ["PatternSubstitution"],
    "passes_with_runtime_observable_failures": ["CodeVirtualization"],
    "behavioral_validation_missing_observations_by_pass": {"CodeVirtualization": 1},
    "passes_with_missing_affected_instruction_evidence": ["CodeVirtualization"],
    "platform_gap_scope": {"formats": ["Mach-O", "PE"], "architectures": ["AArch64", "ARM", "x86"]},
    "corpus_gap_scope": {
        "corpus_families": ["additional-corpus-families"],
        "input_sources": ["generated-inputs"],
    },
}
_EXPECTED_CONTINUOUS_EVIDENCE_BLOCKER_TOTALS = {
    "blocker_categories": len(_EXPECTED_CONTINUOUS_EVIDENCE_BLOCKERS),
    "corpus_gap_scope": 2,
    "metric_missing_runs": len(_EXPECTED_METRIC_RUN_TOTALS),
    "missing_corpus_passes": len(_EXPECTED_MISSING_CORPUS_PASSES),
    "passes_with_incomplete_coverage": len(_EXPECTED_INCOMPLETE_COVERAGE),
    "passes_with_runtime_observable_failures": 1,
    "behavioral_validation_missing_observations_by_pass": 1,
    "passes_with_semantic_failures": 1,
    "passes_with_missing_affected_instruction_evidence": 1,
    "passes_without_applied_runs": 1,
    "platform_gap_scope": 2,
    "total_continuous_evidence_blockers": 29,
}
_EXPECTED_EXTENDED_MATURITY_BLOCKERS = {"missing_extended_passes": _EXPECTED_MISSING_EXTENDED_PASSES}
_EXPECTED_EXTENDED_MATURITY_BLOCKER_TOTALS = {
    "blocker_categories": len(_EXPECTED_EXTENDED_MATURITY_BLOCKERS),
    "missing_extended_passes": len(_EXPECTED_MISSING_EXTENDED_PASSES),
    "total_extended_maturity_evidence_blockers": len(_EXPECTED_MISSING_EXTENDED_PASSES),
}
_BASELINE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "protection_maturity_baseline.py"


def test_measure_fixture_records_real_semantic_result(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    expect(result["all_semantic_equal"] is (sys.platform == "linux"))


def test_runtime_observation_allows_slow_runner_startup(tmp_path: Path) -> None:
    result = asyncio.run(
        _run_runtime(
            [sys.executable, "-c", "import time; time.sleep(5.25)"],
            tmp_path,
        )
    )

    expect(result["status"] == "completed" and result["return_code"] == 0)


def test_varargs_fixture_preserves_vector_abi_exit_code() -> None:
    expect(emulate_exit_code(_VARARGS_FIXTURE) == _EXPECTED_VARARGS_EXIT_CODE)


def test_register_substitution_preserves_pie_live_in_arguments(tmp_path: Path) -> None:
    result = measure_fixture(
        _PIE_FIXTURE,
        range(20260901, 20260902),
        tmp_path,
        "RegisterSubstitution",
    )

    expect(result["runs"][0]["unicorn"]["exit_code"] == _EXPECTED_PIE_EXIT_CODE)


def test_semantic_artifacts_emulates_pie_at_runtime_load_bias() -> None:
    evidence = _semantic_artifacts(_PIE_FIXTURE)

    expect(evidence["status"] == "completed")
    expect(evidence["exit_code"] == _EXPECTED_PIE_EXIT_CODE)
    expect(evidence["load_bias"] != 0)


def test_constant_unfolding_keeps_flag_neutral_instruction_before_branch(tmp_path: Path) -> None:
    mutated = tmp_path / "flag_live"
    mutated.write_bytes(_FLAG_LIVE_FIXTURE.read_bytes())
    with Binary(mutated, writable=True) as binary:
        binary.analyze()
        function = binary.get_functions()[0]
        instruction = next(
            instruction
            for instruction in binary.get_function_disasm(int(function["addr"]))
            if instruction.get("disasm", "").lower() == "mov rsi, 0"
        )
        original_bytes = binary.read_bytes(int(instruction["addr"]), int(instruction["size"]))
        ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260901}).apply(binary)
        expect(binary.read_bytes(int(instruction["addr"]), int(instruction["size"])) == original_bytes)


def test_register_substitution_preserves_varargs_indirect_call_target(tmp_path: Path) -> None:
    result = measure_fixture(
        _VARARGS_FIXTURE,
        range(20260901, 20260902),
        tmp_path,
        "RegisterSubstitution",
    )

    expect(result["runs"][0]["unicorn"]["exit_code"] == _EXPECTED_VARARGS_EXIT_CODE)


def test_packed_indexed_fixture_native_baseline_matches_unicorn() -> None:
    native = _runtime_artifacts(_PACKED_INDEXED_FIXTURE)
    native_matches = sys.platform != "linux" or native.get("return_code") == _EXPECTED_PACKED_INDEXED_EXIT_CODE

    expect(native_matches and emulate_exit_code(_PACKED_INDEXED_FIXTURE) == _EXPECTED_PACKED_INDEXED_EXIT_CODE)


def test_measure_fixture_emits_transformation_evidence(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    evidence = result["runs"][0]["transformation"]
    expect(any(value == "code-virtualization" for value in evidence.values()))


def test_measure_fixture_supports_a_named_non_virtualization_pass(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path, "NopInsertion")

    expect("nop-insertion" in result["runs"][0]["transformation"].values())


def test_measure_fixture_omits_anti_disassembly_without_safe_code_cave(tmp_path: Path) -> None:
    result = measure_fixture(
        _FIXTURE,
        range(20260821, 20260822),
        tmp_path,
        "AntiDisassembly",
    )

    expect(
        result["runs"][0]["transformation"]
        == {
            "pass_name": "anti-disassembly",
            "status": "omitted",
            "reason": "no eligible function was transformed",
        }
    )


def test_omitted_pass_preserves_fixture_without_re_serializing(tmp_path: Path) -> None:
    run = _measure_seed(
        _VEX_WORD_SHUFFLE_FIXTURE,
        20260901,
        tmp_path,
        "SelfModifyingCode",
    )

    expect(run["transformation"]["status"] == "omitted")
    expect(run["output_sha256"] == sha256(_VEX_WORD_SHUFFLE_FIXTURE))


def test_measure_seed_records_pass_construction_errors(tmp_path: Path) -> None:
    run = _measure_seed(_FIXTURE, 20260902, tmp_path, "UnknownPass")

    expect(run["status"] == "error" and run["transformation"]["status"] == "error")


def test_measure_fixture_omits_data_flow_when_no_destination_is_dead(tmp_path: Path) -> None:
    result = measure_fixture(
        _NOP_FIXTURE,
        range(20260820, 20260821),
        tmp_path,
        "DataFlowMutation",
    )
    run = result["runs"][0]

    expect(
        run["transformation"]
        == {
            "pass_name": "data-flow-mutation",
            "status": "omitted",
            "reason": "no eligible function was transformed",
        }
        and run["output_sha256"] == sha256(_NOP_FIXTURE)
    )


def test_measure_fixture_applies_data_flow_on_dead_register_fixture(tmp_path: Path) -> None:
    executable = _compile_elf_x86_64_binary(tmp_path, "data_flow", _DATA_FLOW_SOURCE)
    result = measure_fixture(
        executable,
        range(20260901, 20260902),
        tmp_path,
        "DataFlowMutation",
    )
    run = result["runs"][0]

    expect(
        run["transformation"]["status"] == "applied"
        and run["mutations_applied"] > 0
        and run["unicorn"]["exit_code"] == _EXPECTED_DATA_FLOW_EXIT_CODE
    )


def test_short_jump_patching_uses_trailing_nop_slack_in_real_elf(tmp_path: Path) -> None:
    executable = _compile_elf_x86_64_binary(tmp_path, "shortjump", _SHORT_JUMP_SOURCE)

    with Binary(executable, writable=True) as binary:
        binary.analyze("aa")
        stats = ShortJumpPatchingPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)

    expect(stats["total_patched"] == 1)


def test_measure_fixture_records_short_jump_patching_on_real_fixture(tmp_path: Path) -> None:
    executable = _compile_elf_x86_64_binary(tmp_path, "shortjump", _SHORT_JUMP_SOURCE)
    result = measure_fixture(
        executable,
        range(20260820, 20260821),
        tmp_path,
        "ShortJumpPatching",
    )
    run = result["runs"][0]

    expect(
        run["transformation"]["status"] == "applied"
        and emulate_exit_code(executable) == _EXPECTED_SHORT_JUMP_EXIT_CODE
        and run["unicorn"]["exit_code"] == _EXPECTED_SHORT_JUMP_EXIT_CODE
    )


def test_constant_unfolding_fixture_records_a_semantic_mutation(tmp_path: Path) -> None:
    result = measure_fixture(
        _CONSTANT_UNFOLD_FIXTURE,
        range(20260912, 20260913),
        tmp_path,
        "ConstantUnfolding",
    )

    run = result["runs"][0]
    expect(run["transformation"]["status"] == "applied" and result["all_semantic_equal"] is (sys.platform == "linux"))


def test_dead_code_injection_fixture_records_a_semantic_mutation(tmp_path: Path) -> None:
    result = measure_fixture(
        _DEAD_CODE_FIXTURE,
        range(20260912, 20260913),
        tmp_path,
        "DeadCodeInjection",
    )

    run = result["runs"][0]
    expect(run["transformation"]["status"] == "applied" and result["all_semantic_equal"] is (sys.platform == "linux"))


def test_control_flow_flattening_fixture_records_a_semantic_mutation(tmp_path: Path) -> None:
    result = measure_fixture(
        _CONTROL_FLOW_FIXTURE,
        range(20260912, 20260913),
        tmp_path,
        "ControlFlowFlattening",
    )

    run = result["runs"][0]
    expect(run["transformation"]["status"] == "applied" and result["all_semantic_equal"] is (sys.platform == "linux"))


def test_nop_insertion_fixture_records_a_semantic_mutation(tmp_path: Path) -> None:
    result = measure_fixture(
        _NOP_FIXTURE,
        range(20260912, 20260913),
        tmp_path,
        "NopInsertion",
    )

    run = result["runs"][0]
    expect(run["transformation"]["status"] == "applied" and result["all_semantic_equal"] is (sys.platform == "linux"))


def test_pattern_substitution_fixture_records_a_semantic_mutation(
    tmp_path: Path, deterministic_pattern_subst_elf: Path
) -> None:
    result = measure_fixture(
        deterministic_pattern_subst_elf,
        range(20260912, 20260913),
        tmp_path,
        "PatternSubstitution",
    )

    run = result["runs"][0]
    expect(run["transformation"]["status"] == "applied" and result["all_semantic_equal"] is (sys.platform == "linux"))


def test_render_result_summarizes_size_runtime_and_observables() -> None:
    report = _render_result(
        [
            {
                "all_semantic_equal": False,
                "successful_runs": 1,
                "failed_runs": 1,
                "baseline_size": 100,
                "baseline": {
                    "status": "completed",
                    "metrics": {"number_of_functions": 3, "number_of_instructions": 10},
                },
                "baseline_runtime": {"status": "completed", "duration_seconds": 1.0},
                "runs": [
                    {
                        "status": "passed",
                        "transformation": {"status": "applied"},
                        "output_size": 125,
                        "transform_duration_seconds": 0.5,
                        "runtime": {"status": "completed", "duration_seconds": 1.25},
                        "runtime_observable_equal": True,
                        "after": {
                            "status": "completed",
                            "metrics": {"number_of_functions": 6, "number_of_instructions": 14},
                        },
                    },
                    {
                        "status": "passed",
                        "transformation": {
                            "status": "omitted",
                            "reason": "no eligible function was transformed",
                            "severity": "warning",
                        },
                        "output_size": 95,
                        "transform_duration_seconds": 0.25,
                        "runtime": {"status": "completed", "duration_seconds": 0.75},
                        "runtime_observable_equal": False,
                        "after": {
                            "status": "completed",
                            "metrics": {"number_of_functions": 2, "number_of_instructions": 15},
                        },
                    },
                ],
            }
        ],
        "NopInsertion",
    )

    expect(
        report["summary"]["runtime_observable_passes"] == 1
        and report["summary"]["runtime_observable_failures"] == 1
        and report["summary"]["runtime_observable_failure_reasons"] == {"stdout_missing": 1}
        and report["summary"]["runtime_observable_complete_runs"] == _EXPECTED_RUNTIME_COMPLETE_RUNS
        and report["summary"]["runtime_observable_missing_runs"] == 0
        and report["summary"]["runtime_observable_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["output_size_complete_runs"] == _EXPECTED_OUTPUT_SIZE_COMPLETE_RUNS
        and report["summary"]["output_size_missing_runs"] == 0
        and report["summary"]["output_size_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["total_output_size_delta_bytes"] == _EXPECTED_TOTAL_SIZE_DELTA_BYTES
        and report["summary"]["max_output_size_delta_bytes"] == _EXPECTED_MAX_SIZE_DELTA_BYTES
        and report["summary"]["min_output_size_delta_bytes"] == _EXPECTED_MIN_SIZE_DELTA_BYTES
        and report["summary"]["transform_duration_complete_runs"] == _EXPECTED_TRANSFORM_DURATION_COMPLETE_RUNS
        and report["summary"]["transform_duration_missing_runs"] == 0
        and report["summary"]["transform_duration_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["total_transform_duration_seconds"] == _EXPECTED_TRANSFORM_DURATION_SECONDS
        and report["summary"]["runtime_duration_complete_runs"] == _EXPECTED_RUNTIME_DURATION_COMPLETE_RUNS
        and report["summary"]["runtime_duration_missing_runs"] == 0
        and report["summary"]["runtime_duration_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["total_runtime_duration_delta_seconds"] == 0.0
        and report["summary"]["static_metric_complete_runs"] == _EXPECTED_STATIC_COMPLETE_RUNS
        and report["summary"]["static_metric_missing_runs"] == 0
        and report["summary"]["static_metric_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["complete_evidence_runs"] == _EXPECTED_COMPLETE_EVIDENCE_RUNS
        and report["summary"]["complete_evidence_missing_runs"] == 0
        and report["summary"]["complete_evidence_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["total_static_number_of_functions_delta"] == _EXPECTED_STATIC_FUNCTIONS_DELTA
        and report["summary"]["total_static_number_of_instructions_delta"] == _EXPECTED_STATIC_INSTRUCTIONS_DELTA
        and report["summary"]["omission_reasons"] == {"no eligible function was transformed": 1}
        and report["summary"]["error_reasons"] == {}
        and report["summary"]["omission_severities"] == {"warning": 1}
        and report["summary"]["error_severities"] == {}
    )


def test_behavioral_false_positive_metric_counts_applied_runtime_changes() -> None:
    runtime = {
        "status": "completed",
        "return_code": 0,
        "stdout": {"sha256": "a", "size": 0},
        "stderr": {"sha256": "b", "size": 0},
        "created_files": {},
    }
    changed = {**runtime, "return_code": 1}
    metrics = _behavioral_false_positive_metrics(
        [
            (
                {
                    "baseline_runtime_inputs": [runtime, runtime],
                    "baseline_unicorn": {"status": "completed", "exit_code": 0},
                },
                {
                    "transformation": {"status": "applied"},
                    "runtime_inputs": [runtime, changed],
                    "unicorn": {"status": "completed", "exit_code": 1},
                },
            )
        ]
    )

    expect(
        metrics["behavioral_validation_observations"] == _EXPECTED_BEHAVIORAL_VALIDATION_OBSERVATIONS
        and metrics["behavioral_false_positive_observations"] == _EXPECTED_BEHAVIORAL_FALSE_POSITIVE_OBSERVATIONS
        and metrics["behavioral_validation_missing_observations"] == 0
        and metrics["behavioral_false_positive_rate_percent"] == _EXPECTED_BEHAVIORAL_FALSE_POSITIVE_RATE
        and metrics["independent_semantic_observations"] == 1
        and metrics["independent_semantic_false_positive_observations"] == 1
        and metrics["independent_semantic_missing_observations"] == 0
        and metrics["independent_semantic_false_positive_rate_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
    )


def test_affected_instruction_evidence_catalogues_recorded_mnemonics() -> None:
    evidence = _affected_instruction_evidence(
        [
            {"original_disasm": "lock add dword [rax], ecx"},
            {"original_disasm": "rep movsb"},
            {"original_disasm": ""},
        ]
    )

    expect(
        evidence
        == {
            "affected_instruction_evidence_status": "complete",
            "affected_instruction_mnemonics": ["add", "movsb"],
            "affected_instruction_record_count": 2,
        }
    )


def test_affected_instruction_evidence_marks_missing_records() -> None:
    expect(_affected_instruction_evidence([])["affected_instruction_evidence_status"] == "missing")


def test_affected_instruction_evidence_includes_recorded_metadata_mnemonics() -> None:
    evidence = _affected_instruction_evidence(
        [{"metadata": {"affected_instruction_mnemonics": ["add", "callmem", "add"]}}]
    )

    expect(
        evidence
        == {
            "affected_instruction_evidence_status": "complete",
            "affected_instruction_mnemonics": ["add", "callmem"],
            "affected_instruction_record_count": 1,
        }
    )


def test_affected_instruction_evidence_ignores_virtualization_summary_comments() -> None:
    evidence = _affected_instruction_evidence(
        [
            {
                "original_disasm": "; 11 instructions (control-flow region)",
                "metadata": {"affected_instruction_mnemonics": ["vcall", "mov"]},
            }
        ]
    )

    expect(evidence["affected_instruction_mnemonics"] == ["mov", "vcall"])


def test_render_result_counts_missing_size_and_duration_pairs() -> None:
    report = _render_result(
        [
            {
                "all_semantic_equal": True,
                "successful_runs": 1,
                "failed_runs": 0,
                "baseline_runtime": {"status": "completed"},
                "runs": [
                    {
                        "status": "passed",
                        "transformation": {"status": "applied"},
                        "runtime": {"status": "completed"},
                    }
                ],
            }
        ],
        "NopInsertion",
    )

    expect(
        report["summary"]["output_size_complete_runs"] == 0
        and report["summary"]["output_size_missing_runs"] == 1
        and report["summary"]["transform_duration_complete_runs"] == 0
        and report["summary"]["transform_duration_missing_runs"] == 1
        and report["summary"]["runtime_duration_complete_runs"] == 0
        and report["summary"]["runtime_duration_missing_runs"] == 1
        and report["summary"]["complete_evidence_runs"] == 0
        and report["summary"]["complete_evidence_missing_runs"] == 1
    )


def test_render_result_counts_missing_runtime_pairs() -> None:
    report = _render_result(
        [
            {
                "all_semantic_equal": True,
                "successful_runs": 1,
                "failed_runs": 0,
                "baseline_size": 100,
                "baseline_runtime": {"status": "error"},
                "runs": [
                    {
                        "status": "passed",
                        "transformation": {"status": "applied"},
                        "output_size": 100,
                        "runtime": {"status": "completed"},
                    }
                ],
            }
        ],
        "NopInsertion",
    )

    expect(
        report["summary"]["runtime_observable_complete_runs"] == 0
        and report["summary"]["runtime_observable_missing_runs"] == 1
    )


def test_render_multi_pass_result_summarizes_campaign_coverage() -> None:
    report = _render_multi_pass_result(
        {
            "CodeVirtualization": [
                {
                    "all_semantic_equal": True,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "baseline_size": 100,
                    "baseline": {"status": "completed", "metrics": {"number_of_functions": 1}},
                    "baseline_runtime": {"status": "completed", "duration_seconds": 1.0},
                    "runs": [
                        {
                            "transformation": {"status": "applied"},
                            "output_size": 120,
                            "transform_duration_seconds": 0.5,
                            "runtime": {"status": "completed", "duration_seconds": 1.25, "return_code": 1},
                            "runtime_observable_equal": False,
                            "after": {"status": "completed", "metrics": {"number_of_functions": 2}},
                        }
                    ],
                }
            ],
            "PatternSubstitution": [
                {
                    "all_semantic_equal": False,
                    "successful_runs": 0,
                    "failed_runs": 1,
                    "runs": [
                        {
                            "transformation": {
                                "status": "omitted",
                                "reason": "no eligible function was transformed",
                                "severity": "warning",
                            }
                        }
                    ],
                }
            ],
        }
    )

    expect(
        report["campaign_summary"]["pass_count"] == _EXPECTED_MULTI_PASS_COUNT
        and report["campaign_summary"]["platform_scope"] == {"os": "linux", "format": "ELF", "architecture": "x86-64"}
        and report["campaign_summary"]["platform_gap_scope"]
        == {"formats": ["Mach-O", "PE"], "architectures": ["AArch64", "ARM", "x86"]}
        and report["campaign_summary"]["corpus_gap_scope"]
        == {"corpus_families": ["additional-corpus-families"], "input_sources": ["generated-inputs"]}
        and report["campaign_summary"]["corpus_scope"] == {"dataset": "explicit-fixtures"}
        and report["campaign_summary"]["expected_corpus_pass_count"] == _EXPECTED_CORPUS_PASS_COUNT
        and report["campaign_summary"]["covered_corpus_pass_count"] == _EXPECTED_MULTI_PASS_COUNT
        and report["campaign_summary"]["corpus_pass_coverage_percent"] == _EXPECTED_CORPUS_PASS_COVERAGE_PERCENT
        and report["campaign_summary"]["missing_corpus_passes"] == _EXPECTED_MISSING_CORPUS_PASSES
        and report["campaign_summary"]["expected_extended_pass_count"] == _EXPECTED_EXTENDED_PASS_COUNT
        and report["campaign_summary"]["covered_extended_pass_count"] == 0
        and report["campaign_summary"]["extended_pass_coverage_percent"] == _EXPECTED_EMPTY_COVERAGE_PERCENT
        and report["campaign_summary"]["missing_extended_passes"] == _EXPECTED_MISSING_EXTENDED_PASSES
        and report["campaign_summary"]["passes_without_extended_applied_runs"] == []
        and report["campaign_summary"]["extended_passes_with_error_runs"] == []
        and report["campaign_summary"]["extended_maturity_evidence_blockers"] == _EXPECTED_EXTENDED_MATURITY_BLOCKERS
        and report["campaign_summary"]["extended_maturity_evidence_blocker_totals"]
        == _EXPECTED_EXTENDED_MATURITY_BLOCKER_TOTALS
        and report["campaign_summary"]["passes_without_applied_runs"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_omitted_runs"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_error_runs"] == []
        and report["campaign_summary"]["passes_with_incomplete_coverage"] == _EXPECTED_INCOMPLETE_COVERAGE
        and report["campaign_summary"]["continuous_evidence_blockers"] == _EXPECTED_CONTINUOUS_EVIDENCE_BLOCKERS
        and report["campaign_summary"]["continuous_evidence_blocker_totals"]
        == _EXPECTED_CONTINUOUS_EVIDENCE_BLOCKER_TOTALS
        and report["campaign_summary"]["metric_complete_runs"] == _EXPECTED_METRIC_RUN_TOTALS
        and report["campaign_summary"]["metric_missing_runs"] == _EXPECTED_METRIC_RUN_TOTALS
        and report["campaign_summary"]["passes_with_semantic_failures"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_runtime_observable_failures"] == ["CodeVirtualization"]
        and report["campaign_summary"]["passes_with_missing_affected_instruction_evidence"] == ["CodeVirtualization"]
        and report["campaign_summary"]["runtime_observable_failure_reasons_by_pass"]
        == {"CodeVirtualization": {"return_code": 1}}
        and report["campaign_summary"]["omission_reasons_by_pass"] == _EXPECTED_OMISSION_REASONS_BY_PASS
        and report["campaign_summary"]["error_reasons_by_pass"] == {}
        and report["campaign_summary"]["omission_severities_by_pass"] == _EXPECTED_OMISSION_SEVERITIES_BY_PASS
        and report["campaign_summary"]["error_severities_by_pass"] == {}
        and report["campaign_summary"]["total_classified_runs"] == _EXPECTED_MULTI_PASS_CLASSIFIED_RUNS
        and report["campaign_summary"]["total_applied_runs"] == 1
        and report["campaign_summary"]["total_omitted_runs"] == 1
        and report["campaign_summary"]["total_error_runs"] == 0
        and report["campaign_summary"]["applied_run_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["omitted_run_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["error_run_percent"] == _EXPECTED_EMPTY_COVERAGE_PERCENT
        and report["campaign_summary"]["total_seed_runs"] == _EXPECTED_MULTI_PASS_SEED_RUNS
        and report["campaign_summary"]["total_successful_seed_runs"] == 1
        and report["campaign_summary"]["total_failed_seed_runs"] == 1
        and report["campaign_summary"]["semantic_success_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["semantic_failure_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["average_runtime_observable_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_runtime_observable_complete_runs"] == 1
        and report["campaign_summary"]["total_runtime_observable_missing_runs"] == 1
        and report["campaign_summary"]["average_output_size_coverage_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_output_size_complete_runs"] == 1
        and report["campaign_summary"]["total_output_size_missing_runs"] == 1
        and report["campaign_summary"]["total_output_size_delta_bytes"] == _EXPECTED_CAMPAIGN_OUTPUT_SIZE_DELTA_BYTES
        and report["campaign_summary"]["average_transform_duration_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_transform_duration_complete_runs"] == 1
        and report["campaign_summary"]["total_transform_duration_missing_runs"] == 1
        and report["campaign_summary"]["total_transform_duration_seconds"]
        == _EXPECTED_CAMPAIGN_TRANSFORM_DURATION_SECONDS
        and report["campaign_summary"]["average_runtime_duration_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_runtime_duration_complete_runs"] == 1
        and report["campaign_summary"]["total_runtime_duration_missing_runs"] == 1
        and report["campaign_summary"]["total_runtime_duration_delta_seconds"]
        == _EXPECTED_CAMPAIGN_RUNTIME_DURATION_DELTA_SECONDS
        and report["campaign_summary"]["average_static_metric_coverage_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_static_metric_complete_runs"] == 1
        and report["campaign_summary"]["total_static_metric_missing_runs"] == 1
        and report["campaign_summary"]["total_static_number_of_functions_delta"]
        == _EXPECTED_CAMPAIGN_STATIC_FUNCTIONS_DELTA
        and report["campaign_summary"]["average_complete_evidence_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["total_complete_evidence_runs"] == 1
        and report["campaign_summary"]["total_complete_evidence_missing_runs"] == 1
    )


def test_render_multi_pass_result_records_generated_input_coverage() -> None:
    report = _render_multi_pass_result(
        {
            "NopInsertion": [
                {
                    "all_semantic_equal": True,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "baseline_runtime_inputs": [{"argv": list(arguments)} for arguments in _GENERATED_RUNTIME_INPUTS],
                    "runs": [{"transformation": {"status": "applied"}}],
                }
            ]
        },
        corpus_families=["repository-fixtures", _GENERATED_CORPUS_FAMILY, _GENERATED_CPP_CORPUS_FAMILY],
        corpus_metadata={
            "generated_fixture_count": _EXPECTED_GENERATED_FIXTURE_COUNT,
            "generated_fixture_names": [*_EXPECTED_GENERATED_CORPUS_SOURCES],
        },
    )

    expect(
        report["campaign_summary"]["input_sources"] == ["default-argv", "generated-argv"]
        and report["campaign_summary"]["corpus_families"]
        == ["repository-fixtures", _GENERATED_CORPUS_FAMILY, _GENERATED_CPP_CORPUS_FAMILY]
        and report["campaign_summary"]["generated_fixture_count"] == _EXPECTED_GENERATED_FIXTURE_COUNT
        and report["campaign_summary"]["generated_fixture_names"] == [*_EXPECTED_GENERATED_CORPUS_SOURCES]
        and report["campaign_summary"]["corpus_gap_scope"] == {"corpus_families": [], "input_sources": []}
        and report["campaign_summary"]["continuous_evidence_blockers"].get("corpus_gap_scope") is None
    )


def test_render_multi_pass_result_keeps_cpp_corpus_gap_open() -> None:
    report = _render_multi_pass_result(
        {
            "NopInsertion": [
                {
                    "all_semantic_equal": True,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "baseline_runtime_inputs": [{"argv": list(arguments)} for arguments in _GENERATED_RUNTIME_INPUTS],
                    "runs": [{"transformation": {"status": "applied"}}],
                }
            ]
        },
        corpus_families=["repository-fixtures", _GENERATED_CORPUS_FAMILY],
    )

    expect(
        report["campaign_summary"]["corpus_gap_scope"]
        == {"corpus_families": ["additional-corpus-families"], "input_sources": []}
    )


def test_generated_corpus_includes_branch_memory_and_lookup_shapes() -> None:
    expect(tuple(sorted(_GENERATED_CORPUS_SOURCES)) == _EXPECTED_GENERATED_CORPUS_SOURCES)


def test_generated_corpus_simd_shape_is_explicit() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_simd"]

    expect("vector_size(16)" in source and "simd_u32" in source and "input >> 3" in source)


def test_generated_threads_source_exercises_joined_atomic_worker() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_threads"]

    expect(
        "pthread_create" in source
        and "pthread_join" in source
        and "atomic_fetch_add_explicit" in source
        and "memory_order_seq_cst" in source
    )


def test_generated_signals_source_exercises_handler_and_delivery() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_signals"]

    expect(
        "signal(" in source and "raise(SIGUSR1)" in source and "signal_handler" in source and "sig_atomic_t" in source
    )


def test_generated_cpp_exception_source_preserves_unwind_shape() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_cpp_exceptions"]

    expect("throw std::runtime_error" in source and "catch (const std::runtime_error&)" in source)


def test_generated_calls_source_preserves_direct_and_indirect_call_shapes() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_calls"]

    expect(
        "direct_target(value + 7)" in source
        and "call_target volatile selected_target" in source
        and "selected_target(direct)" in source
    )


def test_generated_branch_source_uses_stable_runtime_input() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_branch"]

    expect('"r2morph"' in source and "argv[i]" not in source)


def test_generated_stack_string_source_preserves_direct_literal_call_shape() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_stack_strings"]

    expect('consume_stack_string("stack-string-native")' in source and ".text.r2morph_stack_cave" in source)


def test_generated_string_source_preserves_implicit_memory_shape() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_string"]

    expect('"rep movsb\\n"' in source and '"memory"' in source)


def test_generated_xlat_source_preserves_implicit_table_lookup_shape() -> None:
    source = _GENERATED_CORPUS_SOURCES["generated_xlat"]

    expect('"xlatb"' in source and '"b"(base)' in source)


def test_generated_corpus_declares_compiler_and_pie_variants() -> None:
    expect(
        tuple(profile[0] for profile in _GENERATED_CORPUS_PROFILES)
        == (
            "gcc-o0",
            "gcc-o1",
            "gcc-o2",
            "gcc-o3",
            "gcc-os",
            "gcc-pie-o2",
            "gcc-static-o2",
            "gcc-stripped-o2",
            "clang-o0",
            "clang-o2",
            "clang-o3",
            "clang-pie-o2",
        )
    )


def test_generated_corpus_declares_cpp_compiler_variants() -> None:
    expect(
        tuple(profile[0] for profile in _GENERATED_CPP_CORPUS_PROFILES)
        == (
            "gxx-o0",
            "gxx-o1",
            "gxx-o2",
            "gxx-o3",
            "gxx-os",
            "gxx-pie-o2",
            "gxx-static-o2",
            "gxx-stripped-o2",
            "clangxx-o0",
            "clangxx-o1",
            "clangxx-o2",
            "clangxx-o3",
            "clangxx-os",
            "clangxx-pie-o2",
            "clangxx-static-o2",
            "clangxx-stripped-o2",
        )
    )


def test_complete_evidence_gate_accepts_full_single_pass_report() -> None:
    report = _render_result(
        [
            {
                "all_semantic_equal": True,
                "successful_runs": 1,
                "failed_runs": 0,
                "baseline_size": 100,
                "baseline": {"status": "completed", "metrics": {"number_of_functions": 1}},
                "baseline_runtime": {"status": "completed", "duration_seconds": 1.0},
                "runs": [
                    {
                        "transformation": {"status": "applied"},
                        "output_size": 120,
                        "transform_duration_seconds": 0.5,
                        "runtime": {"status": "completed", "duration_seconds": 1.25},
                        "after": {"status": "completed", "metrics": {"number_of_functions": 2}},
                    }
                ],
            }
        ]
    )

    expect(_complete_evidence_error(report) is None)


def test_complete_evidence_gate_rejects_incomplete_multi_pass_report() -> None:
    report = _render_multi_pass_result(
        {
            "CodeVirtualization": [
                {
                    "all_semantic_equal": True,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "baseline_size": 100,
                    "baseline": {"status": "completed", "metrics": {"number_of_functions": 1}},
                    "baseline_runtime": {"status": "completed", "duration_seconds": 1.0},
                    "runs": [
                        {
                            "transformation": {"status": "applied"},
                            "output_size": 120,
                            "transform_duration_seconds": 0.5,
                            "runtime": {"status": "completed", "duration_seconds": 1.25},
                            "after": {"status": "completed", "metrics": {"number_of_functions": 2}},
                        }
                    ],
                }
            ],
            "PatternSubstitution": [
                {
                    "all_semantic_equal": True,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "runs": [{"transformation": {"status": "applied"}}],
                }
            ],
        }
    )
    error = _complete_evidence_error(report)

    expect(error is not None and "PatternSubstitution" in error)


def test_render_result_counts_missing_static_metric_pairs() -> None:
    report = _render_result(
        [
            {
                "all_semantic_equal": True,
                "successful_runs": 1,
                "failed_runs": 0,
                "baseline_size": 100,
                "baseline": {"status": "error"},
                "runs": [
                    {
                        "status": "passed",
                        "transformation": {"status": "applied"},
                        "output_size": 100,
                        "after": {"status": "completed", "metrics": {"number_of_functions": 1}},
                    }
                ],
            }
        ],
        "NopInsertion",
    )

    expect(
        report["summary"]["static_metric_complete_runs"] == 0 and report["summary"]["static_metric_missing_runs"] == 1
    )


def test_parse_pass_names_expands_the_public_corpus_selection() -> None:
    expect(_parse_pass_names("all") == CORPUS_PASS_NAMES)


def test_parse_pass_names_accepts_extended_passes_without_expanding_all() -> None:
    selected = _parse_pass_names("AntiDisassembly,APIHashing,PolymorphicEngine")

    expect(
        selected == ("AntiDisassembly", "APIHashing", "PolymorphicEngine") and set(CORPUS_PASS_NAMES) < set(_PASS_TYPES)
    )


def test_baseline_script_runs_directly_from_the_repository(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    result = run_process(
        [sys.executable, str(_BASELINE_SCRIPT), str(_FIXTURE), "--count", "1", "--output", str(output)]
    )

    expect(result.returncode == 0 and output.is_file() and result.stdout == b"")


def test_baseline_script_rejects_a_selected_pass_without_mutations(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    result = run_process(
        [
            sys.executable,
            str(_BASELINE_SCRIPT),
            str(_FIXTURE),
            "--passes",
            "ConstantUnfolding",
            "--require-applied",
            "--count",
            "1",
            "--output",
            str(output),
        ]
    )

    expect(result.returncode != 0 and not output.exists())


def test_transformation_evidence_records_unsupported_capability() -> None:
    evidence = _transformation_evidence(
        "passed",
        {
            "functions_virtualized": 0,
            "unsupported_functions": [
                {"capability": "thread_local_storage", "reason": "TLS addressing not proven", "severity": "error"}
            ],
        },
    )

    expect(
        evidence
        == {
            "pass_name": "code-virtualization",
            "status": "omitted",
            "reason": "thread_local_storage: TLS addressing not proven",
            "severity": "error",
        }
    )


def test_transformation_evidence_records_partial_virtualization_capability() -> None:
    evidence = _transformation_evidence(
        "passed",
        {
            "functions_virtualized": 0,
            "partial_virtualization": [
                {"capability": "floating_point", "reason": "SIMD lane semantics not proven", "severity": "error"}
            ],
        },
    )

    expect(
        evidence
        == {
            "pass_name": "code-virtualization",
            "status": "omitted",
            "reason": "floating_point: SIMD lane semantics not proven",
            "severity": "error",
        }
    )


def test_transformation_evidence_accepts_extended_pass_counters() -> None:
    evidence = _transformation_evidence("passed", {"total_injections": 2}, None, "AntiDisassembly")

    expect(evidence == {"pass_name": "anti-disassembly", "status": "applied", "total_injections": 2})


def test_transformation_evidence_accepts_short_jump_patch_counter() -> None:
    evidence = _transformation_evidence("passed", {"total_patched": 1}, None, "ShortJumpPatching")

    expect(evidence == {"pass_name": "short-jump-patching", "status": "applied", "total_patched": 1})


def test_transformation_evidence_accepts_generic_mutation_counter() -> None:
    evidence = _transformation_evidence("passed", {"mutations_applied": 1}, None, "ImportObfuscation")

    expect(evidence == {"pass_name": "import-obfuscation", "status": "applied", "mutations_applied": 1})


def test_transformation_evidence_does_not_count_stack_string_preview_as_mutation() -> None:
    evidence = _transformation_evidence("passed", {"strings_transformed": 1}, None, "StackStrings")

    expect(evidence["status"] == "omitted")


def test_diagnostic_counts_groups_capabilities_and_severities() -> None:
    diagnostics = [
        {"capability": "memory", "severity": "error"},
        {"capability": "memory", "severity": "warning"},
        {"capability": "abi", "severity": "error"},
    ]

    expect(
        _diagnostic_counts(diagnostics, "capability") == {"abi": 1, "memory": 2}
        and _diagnostic_counts(diagnostics, "severity") == {"error": 2, "warning": 1}
    )


def test_runtime_observables_detect_changed_stdout_digest() -> None:
    baseline = {
        "status": "completed",
        "return_code": 42,
        "stdout": {"sha256": "same", "size": 1},
        "stderr": {"sha256": "empty", "size": 0},
    }
    changed = {**baseline, "stdout": {"sha256": "different", "size": 1}}

    expect(not (_runtime_observables_equal(baseline, changed) is not False))


def test_runtime_observables_reject_matching_launch_errors() -> None:
    failed_runtime = {
        "status": "error",
        "error_type": "OSError",
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
        "created_files": {},
    }

    expect(not (_runtime_observables_equal(failed_runtime, failed_runtime) is not False))


def test_runtime_artifacts_records_files_created_by_real_process(tmp_path: Path) -> None:
    program = tmp_path / "program"
    program.write_text(
        "#!/bin/sh\nprintf created > created.txt\n",
        encoding="utf-8",
    )
    program.chmod(0o700)

    result = _runtime_artifacts(program)

    expect(
        result["created_files"]
        == {
            "created.txt": {
                "sha256": "406effb1e9c59672c66a598c2b21e331b23b16c54024e96d6df3e7c173549791",
                "size": 7,
            }
        }
    )


def test_runtime_artifacts_stabilizes_program_argv_zero(tmp_path: Path) -> None:
    program = tmp_path / "program"
    program.write_text(
        "#!/bin/sh\nprintf '%s' \"$0\"\n",
        encoding="utf-8",
    )
    program.chmod(0o700)

    first = _runtime_artifacts(program)
    second = _runtime_artifacts(program)

    expect(_runtime_observables_equal(first, second))


def test_runtime_artifacts_records_files_before_real_process_timeout(tmp_path: Path) -> None:
    program = tmp_path / "program"
    program.write_text(
        "#!/bin/sh\nprintf started > created.txt\nwhile :; do :; done\n",
        encoding="utf-8",
    )
    program.chmod(0o700)

    result = _runtime_artifacts(program)

    expect(
        result["status"] == "timeout"
        and result["created_files"]
        == {
            "created.txt": {
                "sha256": "03494afd4248c42f5fa1237bf2eeebe751ab8d9c977d55405fcb17469dbd91f8",
                "size": 7,
            }
        }
    )


def test_runtime_observables_detect_changed_created_file() -> None:
    baseline = {
        "status": "completed",
        "return_code": 0,
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
        "created_files": {"result.txt": {"sha256": "same", "size": 1}},
    }
    changed = {**baseline, "created_files": {"result.txt": {"sha256": "different", "size": 1}}}

    expect(not (_runtime_observables_equal(baseline, changed) is not False))


def test_artifact_accumulator_bounds_preview_for_large_stream() -> None:
    accumulator = _ArtifactAccumulator()
    accumulator.update(b"x" * (_PREVIEW_BYTES * 100))
    result = accumulator.result()

    expect(result["size"] == _PREVIEW_BYTES * 100)
    expect(len(result["preview_hex"]) == _PREVIEW_BYTES * 2)


def test_semantic_run_rejects_invalid_emulator_status() -> None:
    baseline = {"status": "completed", "exit_code": 42}
    runtime = {
        "status": "error",
        "error_type": "OSError",
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
    }
    run = {
        "status": "passed",
        "runtime": runtime,
        "unicorn": {"status": "no_exit_syscall", "exit_code": None},
    }

    expect(not (_semantic_run_matches(baseline, runtime, run) is not False))


def test_semantic_run_prefers_matching_qemu_oracle() -> None:
    baseline = {
        "baseline_qemu": {"status": "completed", "exit_code": 42},
        "baseline_unicorn": {"status": "completed", "exit_code": 7},
    }
    runtime = {
        "status": "completed",
        "return_code": 42,
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
        "created_files": {},
    }
    run = {
        "status": "passed",
        "runtime": runtime,
        "qemu": {"status": "completed", "exit_code": 42},
        "unicorn": {"status": "completed", "exit_code": 7},
    }

    expect(_semantic_run_matches(baseline, runtime, run))
    expect(_independent_semantic_pair(baseline, run) == (baseline["baseline_qemu"], run["qemu"]))


def test_semantic_run_uses_native_runtime_when_emulator_lacks_instruction_support() -> None:
    baseline = {"status": "error", "error_type": "UcError"}
    runtime = {
        "status": "completed",
        "return_code": 42,
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
        "created_files": {},
    }
    run = {
        "status": "passed",
        "runtime": runtime,
        "unicorn": {"status": "error", "error_type": "UcError"},
    }

    expect(_semantic_run_matches(baseline, runtime, run))


def test_discover_executables_excludes_relocatable_objects() -> None:
    fixtures = discover_executables(_DATASET)

    expect(_DATASET / "elf_x86_64.o" not in fixtures)


def test_fixture_shard_selection_is_deterministic_and_disjoint() -> None:
    fixtures = [Path(f"fixture-{index}") for index in range(7)]
    shards = [_select_fixture_shard(fixtures, index, 3) for index in range(3)]

    expect(
        shards
        == [
            [fixtures[0], fixtures[3], fixtures[6]],
            [fixtures[1], fixtures[4]],
            [fixtures[2], fixtures[5]],
        ]
        and sorted(path for shard in shards for path in shard) == fixtures
    )


def test_merge_maturity_reports_rechecks_application_across_shards() -> None:
    first_fixture = {"all_semantic_equal": True, "runs": []}
    second_fixture = {"all_semantic_equal": True, "runs": []}
    first = _render_multi_pass_result(
        {"CodeVirtualization": [first_fixture]},
        Path("fixtures/dataset"),
        ["repository-fixtures"],
        {"generated_fixture_names": ["generated_branch_gcc-o0"]},
    )
    second = _render_multi_pass_result(
        {"CodeVirtualization": [second_fixture]},
        Path("fixtures/dataset"),
        ["repository-fixtures"],
        {"generated_fixture_names": ["generated_lookup_gcc-o0"]},
    )

    merged = merge_maturity_reports([first, second])

    expect(
        len(merged["passes"]["CodeVirtualization"]["fixtures"]) == _EXPECTED_MERGED_GENERATED_FIXTURE_COUNT
        and merged["campaign_summary"]["generated_fixture_count"] == _EXPECTED_MERGED_GENERATED_FIXTURE_COUNT
        and merged["campaign_summary"]["corpus_scope"] == {"dataset": "fixtures/dataset"}
    )


def test_generated_fixture_metadata_follows_fixture_shard() -> None:
    fixtures = [Path("repository-0"), Path("repository-1"), Path("generated-a"), Path("generated-b")]
    generated = ["generated-a", "generated-b"]
    shard = _select_fixture_shard(fixtures, 1, 2)

    names, count = _selected_generated_fixture_names(shard, generated, {"index": 1, "count": 2})

    expect(names == ["generated-b"] and count == 1)
