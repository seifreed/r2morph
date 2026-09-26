"""Regression contract for complete analyzer benchmark reporting."""

import json
import os
import sys
from pathlib import Path

import pytest

from scripts.adversarial_benchmark import (
    _ADVERSARIAL_ALL_PASS_NAMES,
    _EXPECTED_TOOLS,
    _analyzer_effectiveness_by_pass,
    _availability,
    _binary_ninja_decompiler_metrics,
    _campaign_summary,
    _decompiler_evidence_complete,
    _decompiler_observations,
    _is_binary_ninja_license_error,
    _measure_pair_tools,
    _measure_tool,
    _measure_tool_bounded,
    _missing_tool_slot_error,
    _parse_adversarial_pass_names,
    _parse_ghidra_decompiler_metrics,
    _parse_ghidra_function_count,
    _parse_ghidra_function_counts,
    _pass_result,
    _pass_summary,
    _passes_without_applications,
    _prepare_optional_module_path,
    _protected_copy,
    _tool_failure_result,
    _tool_summary,
    _ToolCapabilityUnavailableError,
    benchmark_corpus,
    benchmark_pair,
    merge_adversarial_reports,
)
from scripts.adversarial_benchmark import (
    main as adversarial_main,
)
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_ANALYSIS_REQUIRED_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_cff_flaglive_x86_64"
_NOP_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_nop_x86_64"
_PATTERN_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_multiret_jccdiamond_x86_64"
_SINGLE_FIXTURE_REPORT = Path(__file__).resolve().parents[2] / "docs" / "protection-adversarial-benchmark.json"
_COMPATIBILITY_DOC = Path(__file__).resolve().parents[2] / "docs" / "compatibility-corpus.md"
_EXPECTED_TOOL_COUNT = 9
_EXPECTED_GHIDRA_FUNCTION_COUNT = 17
_EXPECTED_TOTAL_TOOL_DURATION_SECONDS = 1.25
_EXPECTED_TOTAL_FUNCTIONS_DELTA = 4
_EXPECTED_TOTAL_INSTRUCTION_LINES_DELTA = 3
_EXPECTED_UNSUPPORTED_CAPABILITY_TOTAL = 3
_EXPECTED_PARTIAL_TOOL_ROWS = 3
_EXPECTED_EMPTY_COVERAGE_PERCENT = 0.0
_EXPECTED_HALF_COVERAGE_PERCENT = 50.0
_EXPECTED_FULL_COVERAGE_PERCENT = 100.0
_EXPECTED_PARTIAL_TOOL_COVERAGE_PERCENT = 33.33
_EXPECTED_TWO_PASS_TOOL_RUNS = 18
_EXPECTED_TWO_PASS_TOOL_MISSING_RUNS = 15
_EXPECTED_TWO_PASS_TOOL_COVERAGE_PERCENT = 16.67
_EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL = 2
_EXPECTED_COMPLETED_TOOL_RUN_COVERAGE_PERCENT = 5.56
_EXPECTED_NON_COMPLETED_TOOL_RUNS = 17
_EXPECTED_MERGED_SAMPLE_COUNT = 2
_EXPECTED_APPLIED_PAIR_COUNT = 1
_EXPECTED_GENERIC_MUTATION_COUNT = 2
_EXPECTED_DECOMPILER_COMPLETION_PERCENT = 100.0
_EXPECTED_DECOMPILER_LINE_DELTA = 3
_EXPECTED_FUNCTION_COUNT_DELTA = 1
_EXPECTED_BINARY_NINJA_DECOMPILER_ENTRYPOINTS = 2
_EXPECTED_BINARY_NINJA_DECOMPILER_LINES = 6


def test_adversarial_benchmark_reports_every_tool_slot() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    tools = report["tools"]
    expect(
        len(tools) == _EXPECTED_TOOL_COUNT
        and {item["tool"] for item in tools} >= {"radare2", "angr", "binary-ninja", "unicorn", "triton"}
    )


def test_adversarial_all_pass_selection_covers_extended_maturity_passes() -> None:
    selected = _parse_adversarial_pass_names("all")

    expect(
        len(selected) == len(_ADVERSARIAL_ALL_PASS_NAMES)
        and "AntiDisassembly" in selected
        and "StringObfuscation" in selected
    )


def test_adversarial_benchmark_separates_capability_gaps_from_adapter_errors() -> None:
    unavailable = _tool_failure_result("unicorn", _ToolCapabilityUnavailableError("unsupported ISA"))
    failed = _tool_failure_result("unicorn", ValueError("adapter failed"))

    expect(
        unavailable == {"tool": "unicorn", "status": "unavailable", "reason": "unsupported ISA"}
        and failed == {"tool": "unicorn", "status": "error", "error_type": "ValueError", "detail": "adapter failed"}
    )


def test_adversarial_benchmark_bounds_an_in_process_analyzer() -> None:
    result = _measure_tool_bounded("angr", _FIXTURE, _FIXTURE, timeout=0.001)

    expect(result["status"] == "error" and result["error_type"] == "ProcessTimeoutError")


def test_adversarial_benchmark_reports_the_bounded_custom_adapter() -> None:
    result = benchmark_pair(_FIXTURE, _FIXTURE)
    custom = next(row for row in result["tools"] if row["tool"] == "custom")

    expect(custom["status"] == "completed" and "original" in custom and "protected" in custom)


def test_adversarial_benchmark_reuses_cached_original_metrics() -> None:
    cached_original = {"status": "completed", "functions": 123}
    rows = _measure_pair_tools(_FIXTURE, _FIXTURE, {"radare2": cached_original})
    radare2 = next(row for row in rows if row["tool"] == "radare2")

    expect(radare2["original"] == cached_original and radare2["protected"] != cached_original)


def test_adversarial_benchmark_reuses_cached_protected_metrics_by_digest() -> None:
    digest = "fixture-digest"
    cached_rows = {
        (tool, digest): {
            "tool": tool,
            "status": "completed",
            "original": {"status": "completed"},
            "protected": {"status": "completed", "functions": 3},
            "changed": True,
        }
        for tool in (*_EXPECTED_TOOLS, "custom")
    }

    rows = _measure_pair_tools(
        _FIXTURE,
        _FIXTURE,
        measurement_cache=cached_rows,
        protected_digest=digest,
    )

    expect(rows == list(cached_rows.values()))


def test_binary_ninja_license_failure_is_reported_as_unavailable() -> None:
    expect(_is_binary_ninja_license_error(RuntimeError("License is not valid")))


def test_binary_ninja_bundle_path_is_added_only_when_present(tmp_path: Path) -> None:
    module_path = tmp_path / "binaryninja"
    module_path.mkdir()
    original = list(sys.path)
    previous = os.environ.get("BINARY_NINJA_PYTHON_PATH")
    try:
        os.environ["BINARY_NINJA_PYTHON_PATH"] = str(module_path)
        _prepare_optional_module_path("binary-ninja")
        expect(str(module_path) in sys.path)
    finally:
        sys.path[:] = original
        if previous is None:
            os.environ.pop("BINARY_NINJA_PYTHON_PATH", None)
        else:
            os.environ["BINARY_NINJA_PYTHON_PATH"] = previous


def test_binary_ninja_decompiler_metrics_bound_hlil_output() -> None:
    class FakeFunction:
        def __init__(self, start: int, hlil: str) -> None:
            self.start = start
            self.hlil = hlil

    metrics = _binary_ninja_decompiler_metrics(
        (
            FakeFunction(0x20, "int later(void) {\n  return 2;\n}"),
            FakeFunction(0x10, "int first(void) {\n  return 1;\n}"),
        )
    )

    expect(
        metrics["decompiler_status"] == "completed"
        and metrics["decompiler_entrypoints"] == _EXPECTED_BINARY_NINJA_DECOMPILER_ENTRYPOINTS
        and metrics["decompiler_lines"] == _EXPECTED_BINARY_NINJA_DECOMPILER_LINES
        and metrics["decompiler_failures"] == 0
    )


def test_adversarial_benchmark_report_preserves_every_tool_slot() -> None:
    report = json.loads(_SINGLE_FIXTURE_REPORT.read_text(encoding="utf-8"))
    tools = {item["tool"]: item["status"] for item in report["tools"]}

    expect(
        len(tools) == _EXPECTED_TOOL_COUNT
        and {"radare2", "objdump", "angr", "binary-ninja", "unicorn", "triton", "ida-pro", "ghidra", "custom"}
        == set(tools)
        and tools["angr"] == "completed"
        and tools["binary-ninja"] in {"unavailable", "completed"}
    )


def test_adversarial_benchmark_pair_report_summarizes_tool_rows() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    expect(report["tool_summary"] == _tool_summary([{"tools": report["tools"]}]))


def test_adversarial_protected_copy_analyzes_before_pass_application(tmp_path: Path) -> None:
    _protected, pass_result = _protected_copy(_ANALYSIS_REQUIRED_FIXTURE, tmp_path, "AntiDisassembly")

    expect(pass_result["status"] == "applied" and pass_result["mutations_applied"] > 0)


def test_adversarial_benchmark_summarizes_analyzer_effectiveness_by_pass() -> None:
    samples = [
        {
            "tools": [
                {
                    "pass_name": "NopInsertion",
                    "tool": "radare2",
                    "status": "completed",
                    "changed": True,
                    "original": {
                        "decompiler_status": "completed",
                        "decompiler_entrypoints": 1,
                        "decompiler_lines": 12,
                        "decompiler_bytes": 240,
                        "functions": 3,
                    },
                    "protected": {
                        "decompiler_status": "completed",
                        "decompiler_entrypoints": 1,
                        "decompiler_lines": 15,
                        "decompiler_bytes": 300,
                        "functions": 4,
                    },
                },
                {
                    "pass_name": "NopInsertion",
                    "tool": "binary-ninja",
                    "status": "unavailable",
                    "reason": "module unavailable",
                },
            ]
        }
    ]

    summary = _campaign_summary(samples, 1, ("NopInsertion",))
    effectiveness = summary["analyzer_effectiveness_by_pass"]

    expect(
        effectiveness == _analyzer_effectiveness_by_pass(samples)
        and effectiveness["NopInsertion"]["radare2"]["completion_percent"] == _EXPECTED_DECOMPILER_COMPLETION_PERCENT
        and effectiveness["NopInsertion"]["radare2"]["decompiler"]["delta_decompiler_lines"]
        == _EXPECTED_DECOMPILER_LINE_DELTA
        and effectiveness["NopInsertion"]["radare2"]["metric_deltas"]["total_functions_delta"]
        == _EXPECTED_FUNCTION_COUNT_DELTA
        and effectiveness["NopInsertion"]["binary-ninja"]["unavailable"] == 1
    )


def test_adversarial_benchmark_separates_applied_decompiler_pairs() -> None:
    completed_metrics = {
        "decompiler_status": "completed",
        "decompiler_entrypoints": 1,
        "decompiler_lines": 12,
        "decompiler_bytes": 240,
    }
    samples = [
        {
            "tools": [
                {
                    "pass_name": "NopInsertion",
                    "pass_status": "applied",
                    "tool": "radare2",
                    "status": "completed",
                    "original": completed_metrics,
                    "protected": completed_metrics,
                }
            ]
        },
        {
            "tools": [
                {
                    "pass_name": "NopInsertion",
                    "pass_status": "no-op",
                    "tool": "radare2",
                    "status": "completed",
                    "original": completed_metrics,
                    "protected": completed_metrics,
                }
            ]
        },
    ]

    decompiler = _campaign_summary(samples, _EXPECTED_MERGED_SAMPLE_COUNT, ("NopInsertion",))[
        "analyzer_effectiveness_by_pass"
    ]["NopInsertion"]["radare2"]["decompiler"]

    expect(
        decompiler["observed_pairs"] == _EXPECTED_MERGED_SAMPLE_COUNT
        and decompiler["completed_pairs"] == _EXPECTED_MERGED_SAMPLE_COUNT
        and decompiler["applied_observed_pairs"] == _EXPECTED_APPLIED_PAIR_COUNT
        and decompiler["applied_completed_pairs"] == _EXPECTED_APPLIED_PAIR_COUNT
        and decompiler["applied_completion_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
    )


def test_decompiler_evidence_accepts_empty_applied_subset() -> None:
    evidence = {
        "observed_pairs": 2,
        "completed_pairs": 2,
        "completion_percent": 100.0,
        "applied_observed_pairs": 0,
        "applied_completed_pairs": 0,
        "applied_completion_percent": 0.0,
    }

    expect(_decompiler_evidence_complete(evidence, 2, 0))


def test_decompiler_evidence_accepts_unavailable_base_for_empty_applied_subset() -> None:
    evidence = {
        "observed_pairs": 2,
        "completed_pairs": 1,
        "completion_percent": 50.0,
        "applied_observed_pairs": 0,
        "applied_completed_pairs": 0,
        "applied_completion_percent": 0.0,
    }

    expect(_decompiler_evidence_complete(evidence, 2, 0))


def test_decompiler_evidence_accepts_unavailable_unapplied_subset() -> None:
    evidence = {
        "observed_pairs": 44,
        "completed_pairs": 44,
        "completion_percent": 97.78,
        "applied_observed_pairs": 3,
        "applied_completed_pairs": 3,
        "applied_completion_percent": 100.0,
    }

    expect(_decompiler_evidence_complete(evidence, 45, 3))


def test_decompiler_evidence_records_unavailable_applied_baseline_as_non_comparable() -> None:
    observations = _decompiler_observations(
        {
            "pass_status": "applied",
            "original": {"decompiler_status": "unavailable"},
            "protected": {"decompiler_status": "completed"},
        }
    )

    expect(
        observations["observed_pairs"] == 0
        and observations["baseline_unavailable_pairs"] == 1
        and observations["applied_observed_pairs"] == 0
        and observations["applied_baseline_unavailable_pairs"] == 1
    )


def test_decompiler_evidence_accepts_complete_comparable_subset_with_baseline_gap() -> None:
    evidence = {
        "observed_pairs": 44,
        "completed_pairs": 44,
        "completion_percent": 100.0,
        "baseline_unavailable_pairs": 1,
        "applied_observed_pairs": 44,
        "applied_completed_pairs": 44,
        "applied_baseline_unavailable_pairs": 1,
        "applied_completion_percent": 100.0,
    }

    expect(_decompiler_evidence_complete(evidence, 45, 45))


def test_decompiler_evidence_rejects_incomplete_applied_subset() -> None:
    evidence = {
        "observed_pairs": 2,
        "completed_pairs": 2,
        "completion_percent": 100.0,
        "applied_observed_pairs": 1,
        "applied_completed_pairs": 1,
        "applied_completion_percent": 50.0,
    }

    expect(not _decompiler_evidence_complete(evidence, 2, 1))


def test_adversarial_benchmark_pair_report_summarizes_release_signoff_blockers() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)
    blockers = report["release_signoff_blockers"]
    unavailable = blockers.get("unavailable_analyzers", {}) if isinstance(blockers, dict) else {}
    totals = report["release_signoff_blocker_totals"]

    expect(
        isinstance(blockers, dict)
        and isinstance(unavailable, dict)
        and isinstance(totals, dict)
        and totals["blocker_categories"] == len(blockers)
        and totals["unavailable_analyzers"] == len(unavailable)
        and totals["total_release_signoff_blockers"] == len(unavailable)
    )


def test_adversarial_benchmark_artifact_summary_matches_tool_rows() -> None:
    report = json.loads(_SINGLE_FIXTURE_REPORT.read_text(encoding="utf-8"))

    expect(
        report["tool_summary"] == _tool_summary([{"tools": report["tools"]}])
        and report["tool_summary"]["angr"]["completed"] == 1
        and report["tool_summary"]["binary-ninja"]["unavailable"] == 1
    )


def test_adversarial_benchmark_report_records_tool_evidence_or_reason() -> None:
    report = json.loads(_SINGLE_FIXTURE_REPORT.read_text(encoding="utf-8"))

    expect(
        all("original" in item and "protected" in item for item in report["tools"] if item["status"] == "completed")
        and all(item.get("reason") for item in report["tools"] if item["status"] == "unavailable")
    )


def test_adversarial_benchmark_docs_match_local_tool_availability() -> None:
    report = json.loads(_SINGLE_FIXTURE_REPORT.read_text(encoding="utf-8"))
    tools = {item["tool"]: item["status"] for item in report["tools"]}
    document = " ".join(_COMPATIBILITY_DOC.read_text(encoding="utf-8").split())

    expect(
        tools["angr"] == "completed"
        and tools["binary-ninja"] == "unavailable"
        and "reported as unavailable rather than omitted" in document
        and "angr`, Unicorn, radare2, objdump, and the custom analyzer completed" in document
        and "Binary Ninja, IDA, Ghidra, and Triton are explicit local availability gaps" in document
    )


def test_adversarial_benchmark_marks_missing_tools_explicitly() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    statuses = {item["tool"]: item["status"] for item in report["tools"]}
    expect(
        statuses["binary-ninja"] in {"unavailable", "completed"} and statuses["ida-pro"] in {"unavailable", "completed"}
    )


def test_adversarial_benchmark_runs_triton_when_available() -> None:
    result = _measure_tool("triton", _FIXTURE, _FIXTURE)

    expect(
        result["status"] == "unavailable"
        or (
            result["status"] == "completed"
            and result["original"]["decoded_instructions"] > 0
            and result["protected"]["semantically_supported_instructions"] > 0
        )
    )


def test_adversarial_benchmark_records_angr_decompiler_output_when_available() -> None:
    result = _measure_tool("angr", _FIXTURE, _FIXTURE)

    if result["status"] == "unavailable":
        expect(result.get("reason"))
        return
    expect(
        result["status"] == "completed"
        and result["original"]["decompiler_status"] == "completed"
        and result["protected"]["decompiler_status"] == "completed"
        and result["original"]["decompiler_entrypoints"] > 0
        and result["protected"]["decompiler_lines"] > 0
    )


def test_adversarial_benchmark_uses_compatible_angr_import_boundary() -> None:
    available, reason = _availability("angr")

    if not available:
        expect(bool(reason))
        return

    result = _measure_tool("angr", _FIXTURE, _FIXTURE)
    expect(result["status"] == "completed", f"angr benchmark failed after compatible import: {result}")


def test_adversarial_benchmark_reports_radare2_decompiler_recovery() -> None:
    result = _measure_tool("radare2", _FIXTURE, _FIXTURE)

    expect(
        result["status"] == "completed"
        and result["original"]["decompiler_status"] == "completed"
        and result["protected"]["decompiler_status"] == "completed"
        and result["original"]["decompiler_entrypoints"] > 0
        and result["protected"]["decompiler_lines"] > 0
    )


def test_adversarial_benchmark_parses_ghidra_decompiler_metrics() -> None:
    metrics = _parse_ghidra_decompiler_metrics("R2MORPH_DECOMPILER=fixture=3=27=512")

    expect(metrics == {"fixture": {"decompiler_entrypoints": 3, "decompiler_lines": 27, "decompiler_bytes": 512}})


def test_adversarial_benchmark_corpus_reports_each_sample_and_pass(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    source = _FIXTURE.read_bytes()
    (dataset / _FIXTURE.name).write_bytes(source)

    report = benchmark_corpus(dataset)

    expect(
        report["sample_count"] == 1
        and report["corpus_scope"]
        == {
            "families": ["repository-fixtures"],
            "generated_fixture_count": 0,
            "generated_fixture_names": [],
        }
        and report["summary"]["expected_pass_count"] == 1
        and report["summary"]["observed_pass_count"] == 1
        and report["summary"]["expected_pass_runs"] == 1
        and report["summary"]["observed_pass_runs"] == 1
        and report["summary"]["missing_pass_runs"] == 0
        and report["summary"]["pass_run_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and report["summary"]["expected_tools"] == [*_EXPECTED_TOOLS, "custom"]
        and report["summary"]["observed_tools"] == sorted([*_EXPECTED_TOOLS, "custom"])
        and report["summary"]["expected_tool_count"] == _EXPECTED_TOOL_COUNT
        and report["summary"]["observed_tool_count"] == _EXPECTED_TOOL_COUNT
        and report["summary"]["expected_tool_runs"] == _EXPECTED_TOOL_COUNT
        and report["summary"]["observed_tool_runs"] == _EXPECTED_TOOL_COUNT
        and report["summary"]["missing_tool_runs"] == 0
        and report["summary"]["tool_run_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and "binary-ninja" in report["tool_summary"]
    )
    sample = report["samples"][0]
    expect("CodeVirtualization" in sample["passes"][0].values())


def test_merge_adversarial_reports_rechecks_disjoint_sample_scope() -> None:
    reports = [
        {
            "corpus": "dataset",
            "pass_names": ["CodeVirtualization"],
            "samples": [
                {
                    "original": "fixture-a",
                    "passes": [{"pass_name": "CodeVirtualization", "status": "applied"}],
                    "tools": [],
                }
            ],
        },
        {
            "corpus": "dataset",
            "pass_names": ["CodeVirtualization"],
            "samples": [
                {
                    "original": "fixture-b",
                    "passes": [{"pass_name": "CodeVirtualization", "status": "applied"}],
                    "tools": [],
                }
            ],
        },
    ]

    merged = merge_adversarial_reports(reports)

    expect(
        merged["sample_count"] == _EXPECTED_MERGED_SAMPLE_COUNT
        and merged["summary"]["expected_pass_runs"] == _EXPECTED_MERGED_SAMPLE_COUNT
    )


def test_merge_adversarial_reports_rejects_missing_fixture_shards() -> None:
    reports = [
        {
            "corpus": "dataset",
            "pass_names": ["CodeVirtualization"],
            "fixture_shard": {"index": 0, "count": 3},
            "samples": [],
        },
        {
            "corpus": "dataset",
            "pass_names": ["CodeVirtualization"],
            "fixture_shard": {"index": 2, "count": 3},
            "samples": [],
        },
    ]

    with pytest.raises(ValueError, match="do not cover every fixture shard"):
        merge_adversarial_reports(reports)


def test_adversarial_benchmark_cli_honors_single_fixture_pass_selection(tmp_path: Path) -> None:
    output = tmp_path / "nop-adversarial.json"
    adversarial_main(
        [
            str(_NOP_FIXTURE),
            "--passes",
            "NopInsertion",
            "--output",
            str(output),
        ]
    )
    report = json.loads(output.read_text(encoding="utf-8"))

    expect(
        report.get("pass_names") == ["NopInsertion"]
        and report.get("passes", [{}])[0].get("pass_name") == "NopInsertion",
    )


def test_adversarial_benchmark_output_file_suppresses_report_echo(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nop-adversarial.json"
    adversarial_main(
        [
            str(_NOP_FIXTURE),
            "--passes",
            "NopInsertion",
            "--output",
            str(output),
        ]
    )

    expect(capsys.readouterr().out == "")


def test_adversarial_benchmark_campaign_summary_separates_errors_from_missing_rows() -> None:
    summary = _campaign_summary(
        [
            {
                "passes": [
                    {"pass_name": "CodeVirtualization", "status": "applied"},
                    {"pass_name": "PatternSubstitution", "status": "omitted", "reason": "no eligible pattern"},
                ],
                "tools": [
                    {"tool": "binary-ninja", "status": "completed"},
                    {"tool": "ida-pro", "status": "error", "error_type": "RuntimeError"},
                    {"tool": "ghidra", "status": "unavailable", "reason": "missing local executable"},
                ],
            }
        ],
        fixture_count=1,
        pass_names=("CodeVirtualization", "PatternSubstitution"),
    )

    expect(
        summary["missing_pass_runs"] == 0
        and summary["pass_run_coverage_percent"] == _EXPECTED_FULL_COVERAGE_PERCENT
        and summary["missing_passes"] == []
        and summary["missing_pass_runs_by_pass"] == {}
        and summary["applied_pass_runs"] == 1
        and summary["applied_pass_run_percent"] == _EXPECTED_HALF_COVERAGE_PERCENT
        and summary["applied_pass_runs_by_pass"] == {"CodeVirtualization": 1}
        and summary["omitted_pass_runs"] == 1
        and summary["omitted_pass_run_percent"] == _EXPECTED_HALF_COVERAGE_PERCENT
        and summary["omitted_pass_runs_by_pass"] == {"PatternSubstitution": 1}
        and summary["omission_reasons_by_pass"] == {"PatternSubstitution": {"no eligible pattern": 1}}
        and summary["error_pass_runs"] == 0
        and summary["error_pass_run_percent"] == _EXPECTED_EMPTY_COVERAGE_PERCENT
        and summary["error_pass_runs_by_pass"] == {}
        and summary["error_reasons_by_pass"] == {}
        and summary["expected_tools"] == [*_EXPECTED_TOOLS, "custom"]
        and summary["observed_tools"] == ["binary-ninja", "ghidra", "ida-pro"]
        and summary["expected_tool_runs"] == _EXPECTED_TWO_PASS_TOOL_RUNS
        and summary["observed_tool_runs"] == _EXPECTED_PARTIAL_TOOL_ROWS
        and summary["missing_tool_runs"] == _EXPECTED_TWO_PASS_TOOL_MISSING_RUNS
        and summary["tool_run_coverage_percent"] == _EXPECTED_TWO_PASS_TOOL_COVERAGE_PERCENT
        and {"angr", "custom"}.issubset(summary["missing_tools"])
        and summary["missing_tool_runs_by_tool"]["angr"] == _EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL
        and summary["missing_tool_runs_by_tool"]["custom"] == _EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL
        and summary["completed_tool_runs"] == 1
        and summary["completed_tool_count"] == 1
        and summary["completed_tools"] == ["binary-ninja"]
        and summary["completed_tool_runs_by_tool"] == {"binary-ninja": 1}
        and summary["completed_tool_run_coverage_by_tool"] == {"binary-ninja": _EXPECTED_HALF_COVERAGE_PERCENT}
        and summary["completed_tool_run_percent"] == _EXPECTED_PARTIAL_TOOL_COVERAGE_PERCENT
        and summary["completed_tool_run_coverage_percent"] == _EXPECTED_COMPLETED_TOOL_RUN_COVERAGE_PERCENT
        and {
            row["tool"]: row
            for row in summary["incomplete_tool_coverage"]
            if row["tool"] in {"angr", "binary-ninja", "ghidra"}
        }
        == {
            "angr": {
                "tool": "angr",
                "completed_runs": 0,
                "missing_runs": _EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL,
                "unavailable_runs": 0,
                "error_runs": 0,
                "completed_run_coverage_percent": _EXPECTED_EMPTY_COVERAGE_PERCENT,
            },
            "binary-ninja": {
                "tool": "binary-ninja",
                "completed_runs": 1,
                "missing_runs": 1,
                "unavailable_runs": 0,
                "error_runs": 0,
                "completed_run_coverage_percent": _EXPECTED_HALF_COVERAGE_PERCENT,
            },
            "ghidra": {
                "tool": "ghidra",
                "completed_runs": 0,
                "missing_runs": 1,
                "unavailable_runs": 1,
                "error_runs": 0,
                "completed_run_coverage_percent": _EXPECTED_EMPTY_COVERAGE_PERCENT,
            },
        }
        and summary["non_completed_tool_runs"] == _EXPECTED_NON_COMPLETED_TOOL_RUNS
        and summary["non_completed_tool_runs_by_tool"]["binary-ninja"] == 1
        and summary["non_completed_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL
        and summary["non_completed_tool_runs_by_tool"]["ghidra"] == _EXPECTED_MISSING_RUNS_PER_UNOBSERVED_TOOL
        and len(summary["tools_without_full_completion"]) == _EXPECTED_TOOL_COUNT
        and {"angr", "binary-ninja", "ghidra"}.issubset(summary["tools_without_full_completion"])
        and summary["unavailable_tool_runs"] == 1
        and summary["unavailable_tool_count"] == 1
        and summary["unavailable_tools"] == ["ghidra"]
        and summary["unavailable_tool_run_percent"] == _EXPECTED_PARTIAL_TOOL_COVERAGE_PERCENT
        and summary["unavailable_tool_runs_by_tool"] == {"ghidra": 1}
        and summary["unavailable_reasons_by_tool"] == {"ghidra": {"missing local executable": 1}}
        and summary["error_tool_runs"] == 1
        and summary["error_tool_count"] == 1
        and summary["error_tools"] == ["ida-pro"]
        and summary["error_tool_run_percent"] == _EXPECTED_PARTIAL_TOOL_COVERAGE_PERCENT
        and summary["error_tool_runs_by_tool"] == {"ida-pro": 1}
        and summary["error_reasons_by_tool"] == {"ida-pro": {"RuntimeError": 1}}
        and summary["adversarial_evidence_blockers"]["passes_without_applied_runs"] == ["PatternSubstitution"]
        and "missing_passes" not in summary["adversarial_evidence_blockers"]
        and summary["adversarial_evidence_blockers"]["missing_tool_runs_by_tool"]["binary-ninja"] == 1
        and "incomplete_tool_coverage" in summary["adversarial_evidence_blockers"]
        and "non_completed_tool_runs_by_tool" in summary["adversarial_evidence_blockers"]
        and summary["adversarial_evidence_blockers"]["tools_without_full_completion"]
        == summary["tools_without_full_completion"]
        and summary["adversarial_evidence_blockers"]["unavailable_tool_runs_by_tool"] == {"ghidra": 1}
        and summary["adversarial_evidence_blockers"]["unavailable_reasons_by_tool"]
        == {"ghidra": {"missing local executable": 1}}
        and summary["adversarial_evidence_blocker_totals"]["blocker_categories"]
        == len(summary["adversarial_evidence_blockers"])
        and summary["adversarial_evidence_blocker_totals"]["tools_without_full_completion"] == _EXPECTED_TOOL_COUNT
        and summary["adversarial_evidence_blocker_totals"]["incomplete_tool_coverage"] == _EXPECTED_TOOL_COUNT
        and summary["adversarial_evidence_blocker_totals"]["total_adversarial_evidence_blockers"]
        == sum(
            count
            for field, count in summary["adversarial_evidence_blocker_totals"].items()
            if field not in {"blocker_categories", "total_adversarial_evidence_blockers"}
        )
    )


def test_adversarial_benchmark_tool_slot_gate_accepts_unavailable_rows() -> None:
    tools = [
        {"tool": tool, "status": "unavailable", "reason": "local tool unavailable"}
        for tool in (*_EXPECTED_TOOLS, "custom")
    ]
    report = {
        "summary": _campaign_summary(
            [{"passes": [{"pass_name": "CodeVirtualization", "status": "applied"}], "tools": tools}],
            fixture_count=1,
            pass_names=("CodeVirtualization",),
        )
    }

    expect(_missing_tool_slot_error(report) is None)


def test_adversarial_benchmark_tool_slot_gate_rejects_missing_rows() -> None:
    report = {
        "summary": _campaign_summary(
            [
                {
                    "passes": [{"pass_name": "CodeVirtualization", "status": "applied"}],
                    "tools": [{"tool": "custom", "status": "completed"}],
                }
            ],
            fixture_count=1,
            pass_names=("CodeVirtualization",),
        )
    }
    error = _missing_tool_slot_error(report)

    expect(error is not None and "missing analyzer tool slots" in error and "angr" in error)


def test_adversarial_benchmark_corpus_aggregates_results_by_pass(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / _FIXTURE.name).write_bytes(_FIXTURE.read_bytes())

    report = benchmark_corpus(dataset)

    expect(
        report["pass_summary"]["CodeVirtualization"]
        == {
            "applied": 1,
            "errors": 0,
            "functions_virtualized": 1,
            "no_op": 0,
            "omitted": 0,
            "partial_virtualization": 0,
            "samples": 1,
            "unsupported_functions": 0,
        }
    )


def test_adversarial_benchmark_corpus_summarizes_results_by_tool() -> None:
    summary = _tool_summary(
        [
            {
                "tools": [
                    {
                        "tool": "binary-ninja",
                        "status": "completed",
                        "changed": True,
                        "original": {"duration_seconds": 0.5, "functions": 10, "instruction_lines": 5},
                        "protected": {"duration_seconds": 0.75, "functions": 14, "instruction_lines": 8},
                    },
                    {"tool": "ghidra", "status": "unavailable", "reason": "missing local executable"},
                    {"tool": "ida-pro", "status": "error", "error_type": "RuntimeError"},
                ]
            }
        ]
    )

    expect(
        summary["binary-ninja"]["completed"] == 1
        and summary["binary-ninja"]["changed"] == 1
        and summary["binary-ninja"]["duration_pairs"] == 1
        and summary["binary-ninja"]["total_duration_seconds"] == _EXPECTED_TOTAL_TOOL_DURATION_SECONDS
        and summary["binary-ninja"]["metric_functions_pairs"] == 1
        and summary["binary-ninja"]["total_functions_delta"] == _EXPECTED_TOTAL_FUNCTIONS_DELTA
        and summary["binary-ninja"]["metric_instruction_lines_pairs"] == 1
        and summary["binary-ninja"]["total_instruction_lines_delta"] == _EXPECTED_TOTAL_INSTRUCTION_LINES_DELTA
        and summary["ghidra"]["unavailable"] == 1
        and summary["ghidra"]["unavailable_reasons"] == {"missing local executable": 1}
        and summary["ida-pro"]["errors"] == 1
        and summary["ida-pro"]["error_reasons"] == {"RuntimeError": 1}
    )


def test_adversarial_benchmark_corpus_measures_pattern_substitution(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / _PATTERN_FIXTURE.name).write_bytes(_PATTERN_FIXTURE.read_bytes())

    report = benchmark_corpus(dataset, ("PatternSubstitution",))

    expect(
        report["pass_summary"]["PatternSubstitution"]["applied"] == 1
        and report["pass_summary"]["PatternSubstitution"]["mutations_applied"] == 1
    )


def test_adversarial_benchmark_pass_result_preserves_unsupported_capability_counts() -> None:
    result = _pass_result(
        {
            "functions_virtualized": 0,
            "unsupported_functions_total": 2,
            "partial_virtualization_total": 1,
            "unsupported_functions": [
                {"capability": "computed_control_flow", "reason": "indirect branch not proven", "severity": "error"},
                {"capability": "computed_control_flow", "severity": "error"},
            ],
            "partial_virtualization": [{"capability": "exceptions_and_unwinding", "severity": "warning"}],
        }
    )

    expect(
        result["status"] == "omitted"
        and result["reason"] == "computed_control_flow: indirect branch not proven"
        and result["unsupported_capabilities"] == {"computed_control_flow": 2}
        and result["partial_virtualization_capabilities"] == {"exceptions_and_unwinding": 1}
        and result["unsupported_severities"] == {"error": 2}
        and result["partial_virtualization_severities"] == {"warning": 1}
    )


def test_adversarial_benchmark_pass_result_counts_generic_mutation_evidence() -> None:
    result = _pass_result({"blocks_moved": _EXPECTED_GENERIC_MUTATION_COUNT}, "CodeMobility")

    expect(result["status"] == "applied" and result["mutations_applied"] == _EXPECTED_GENERIC_MUTATION_COUNT)


def test_adversarial_benchmark_pass_result_omits_partial_virtualization_without_unsupported_functions() -> None:
    result = _pass_result(
        {
            "functions_virtualized": 0,
            "unsupported_functions_total": 0,
            "partial_virtualization_total": 1,
            "partial_virtualization": [
                {"capability": "floating_point", "reason": "SIMD lane semantics not proven", "severity": "error"}
            ],
        }
    )

    expect(
        result["status"] == "omitted"
        and result["reason"] == "floating_point: SIMD lane semantics not proven"
        and result["partial_virtualization_capabilities"] == {"floating_point": 1}
        and result["partial_virtualization_severities"] == {"error": 1}
    )


def test_adversarial_benchmark_pass_summary_aggregates_virtualization_capabilities() -> None:
    summary = _pass_summary(
        [
            {
                "passes": [
                    {
                        "pass_name": "CodeVirtualization",
                        "status": "omitted",
                        "reason": "computed_control_flow: indirect branch not proven",
                        "functions_virtualized": 0,
                        "unsupported_functions": 2,
                        "partial_virtualization": 1,
                        "unsupported_capabilities": {"computed_control_flow": 2},
                        "partial_virtualization_capabilities": {"exceptions_and_unwinding": 1},
                        "unsupported_severities": {"error": 2},
                        "partial_virtualization_severities": {"warning": 1},
                    },
                    {
                        "pass_name": "CodeVirtualization",
                        "status": "omitted",
                        "reason": "memory_access: memory model not proven",
                        "functions_virtualized": 0,
                        "unsupported_functions": 1,
                        "partial_virtualization": 0,
                        "unsupported_capabilities": {"memory_access": 1},
                        "unsupported_severities": {"error": 1},
                    },
                ]
            }
        ]
    )

    expect(
        summary["CodeVirtualization"]["unsupported_functions"] == _EXPECTED_UNSUPPORTED_CAPABILITY_TOTAL
        and summary["CodeVirtualization"]["partial_virtualization"] == 1
        and summary["CodeVirtualization"]["unsupported_capabilities"]
        == {"computed_control_flow": 2, "memory_access": 1}
        and summary["CodeVirtualization"]["partial_virtualization_capabilities"] == {"exceptions_and_unwinding": 1}
        and summary["CodeVirtualization"]["unsupported_severities"] == {"error": 3}
        and summary["CodeVirtualization"]["partial_virtualization_severities"] == {"warning": 1}
        and summary["CodeVirtualization"]["omission_reasons"]
        == {
            "computed_control_flow: indirect branch not proven": 1,
            "memory_access: memory model not proven": 1,
        }
    )


def test_adversarial_benchmark_identifies_passes_without_applications() -> None:
    report = {
        "pass_summary": {
            "Applied": {"applied": 1},
            "NoOp": {"applied": 0},
        }
    }

    expect(_passes_without_applications(report) == ("NoOp",))


def test_adversarial_benchmark_parses_ghidra_function_count_marker() -> None:
    expect(_parse_ghidra_function_count("INFO R2MORPH_FUNCTION_COUNT=sample=17") == _EXPECTED_GHIDRA_FUNCTION_COUNT)


def test_adversarial_benchmark_parses_ghidra_function_counts_by_program() -> None:
    expect(
        _parse_ghidra_function_counts("R2MORPH_FUNCTION_COUNT=one=2\nR2MORPH_FUNCTION_COUNT=two=3")
        == {"one": 2, "two": 3}
    )
