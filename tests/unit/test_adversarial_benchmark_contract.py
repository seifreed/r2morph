"""Regression contract for complete analyzer benchmark reporting."""

import json
from pathlib import Path

from scripts.adversarial_benchmark import (
    _EXPECTED_TOOLS,
    _campaign_summary,
    _measure_tool,
    _missing_tool_slot_error,
    _parse_ghidra_function_count,
    _parse_ghidra_function_counts,
    _pass_result,
    _pass_summary,
    _passes_without_applications,
    _tool_summary,
    benchmark_corpus,
    benchmark_pair,
)
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
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


def test_adversarial_benchmark_reports_every_tool_slot() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    tools = report["tools"]
    expect(
        len(tools) == _EXPECTED_TOOL_COUNT
        and {item["tool"] for item in tools} >= {"radare2", "angr", "binary-ninja", "unicorn", "triton"}
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


def test_adversarial_benchmark_corpus_reports_each_sample_and_pass(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    source = _FIXTURE.read_bytes()
    (dataset / _FIXTURE.name).write_bytes(source)

    report = benchmark_corpus(dataset)

    expect(
        report["sample_count"] == 1
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
        and "incomplete_tool_coverage" in summary["adversarial_evidence_blockers"]
        and "non_completed_tool_runs_by_tool" in summary["adversarial_evidence_blockers"]
        and summary["adversarial_evidence_blockers"]["tools_without_full_completion"]
        == summary["tools_without_full_completion"]
        and summary["adversarial_evidence_blockers"]["unavailable_tool_runs_by_tool"] == {"ghidra": 1}
        and summary["adversarial_evidence_blockers"]["unavailable_reasons_by_tool"]
        == {"ghidra": {"missing local executable": 1}}
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
