"""Regression coverage for the real protection maturity measurement harness."""

from __future__ import annotations

import sys
from pathlib import Path

from r2morph.adapters.process import run_process
from scripts.protection_maturity_baseline import (
    _PREVIEW_BYTES,
    CORPUS_PASS_NAMES,
    _ArtifactAccumulator,
    _parse_pass_names,
    _render_multi_pass_result,
    _render_result,
    _runtime_artifacts,
    _runtime_observables_equal,
    _semantic_run_matches,
    _transformation_evidence,
    discover_executables,
    measure_fixture,
)
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
_EXPECTED_PIE_EXIT_CODE = 73
_EXPECTED_PACKED_INDEXED_EXIT_CODE = 6
_EXPECTED_VARARGS_EXIT_CODE = 69
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
_EXPECTED_FULL_COVERAGE_PERCENT = 100.0
_EXPECTED_MULTI_PASS_COUNT = 2
_EXPECTED_MULTI_PASS_CLASSIFIED_RUNS = 2
_EXPECTED_MULTI_PASS_SEED_RUNS = 2
_EXPECTED_AVERAGE_COVERAGE_PERCENT = 50.0
_EXPECTED_EMPTY_COVERAGE_PERCENT = 0.0
_EXPECTED_INCOMPLETE_COVERAGE = {
    "runtime_observable": ["PatternSubstitution"],
    "output_size": ["PatternSubstitution"],
    "transform_duration": ["PatternSubstitution"],
    "runtime_duration": ["PatternSubstitution"],
    "static_metric": ["PatternSubstitution"],
    "complete_evidence": ["PatternSubstitution"],
}
_EXPECTED_OMISSION_REASONS_BY_PASS = {"PatternSubstitution": {"no eligible function was transformed": 1}}
_EXPECTED_OMISSION_SEVERITIES_BY_PASS = {"PatternSubstitution": {"warning": 1}}
_BASELINE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "protection_maturity_baseline.py"


def test_measure_fixture_records_real_semantic_result(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    expect(result["all_semantic_equal"] is (sys.platform == "linux"))


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


def test_pattern_substitution_fixture_records_a_semantic_mutation(tmp_path: Path) -> None:
    result = measure_fixture(
        _CONTROL_FLOW_FIXTURE,
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
                            "runtime": {"status": "completed", "duration_seconds": 1.25},
                            "runtime_observable_equal": True,
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
        and report["campaign_summary"]["passes_without_applied_runs"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_omitted_runs"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_error_runs"] == []
        and report["campaign_summary"]["passes_with_incomplete_coverage"] == _EXPECTED_INCOMPLETE_COVERAGE
        and report["campaign_summary"]["passes_with_semantic_failures"] == ["PatternSubstitution"]
        and report["campaign_summary"]["passes_with_runtime_observable_failures"] == []
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
        and report["campaign_summary"]["average_output_size_coverage_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["average_transform_duration_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["average_runtime_duration_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["average_static_metric_coverage_percent"] == _EXPECTED_AVERAGE_COVERAGE_PERCENT
        and report["campaign_summary"]["average_complete_evidence_coverage_percent"]
        == _EXPECTED_AVERAGE_COVERAGE_PERCENT
    )


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


def test_baseline_script_runs_directly_from_the_repository(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    result = run_process(
        [sys.executable, str(_BASELINE_SCRIPT), str(_FIXTURE), "--count", "1", "--output", str(output)]
    )

    expect(result.returncode == 0 and output.is_file())


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
