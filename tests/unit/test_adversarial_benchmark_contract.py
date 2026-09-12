"""Regression contract for complete analyzer benchmark reporting."""

from pathlib import Path

from scripts.adversarial_benchmark import (
    _measure_tool,
    _parse_ghidra_function_count,
    _parse_ghidra_function_counts,
    _passes_without_applications,
    _tool_summary,
    benchmark_corpus,
    benchmark_pair,
)
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_PATTERN_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_multiret_jccdiamond_x86_64"
_EXPECTED_TOOL_COUNT = 9
_EXPECTED_GHIDRA_FUNCTION_COUNT = 17
_EXPECTED_TOTAL_TOOL_DURATION_SECONDS = 1.25


def test_adversarial_benchmark_reports_every_tool_slot() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    tools = report["tools"]
    expect(
        len(tools) == _EXPECTED_TOOL_COUNT
        and {item["tool"] for item in tools} >= {"radare2", "angr", "binary-ninja", "unicorn", "triton"}
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

    expect(report["sample_count"] == 1 and "binary-ninja" in report["tool_summary"])
    sample = report["samples"][0]
    expect("CodeVirtualization" in sample["passes"][0].values())


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
                        "original": {"duration_seconds": 0.5},
                        "protected": {"duration_seconds": 0.75},
                    },
                    {"tool": "ghidra", "status": "unavailable"},
                    {"tool": "ida-pro", "status": "error"},
                ]
            }
        ]
    )

    expect(
        summary["binary-ninja"]["completed"] == 1
        and summary["binary-ninja"]["changed"] == 1
        and summary["binary-ninja"]["total_duration_seconds"] == _EXPECTED_TOTAL_TOOL_DURATION_SECONDS
        and summary["ghidra"]["unavailable"] == 1
        and summary["ida-pro"]["errors"] == 1
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
