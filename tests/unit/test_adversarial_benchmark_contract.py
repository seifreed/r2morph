"""Regression contract for complete analyzer benchmark reporting."""

from pathlib import Path

from scripts.adversarial_benchmark import (
    _measure_tool,
    _parse_ghidra_function_count,
    _parse_ghidra_function_counts,
    benchmark_corpus,
    benchmark_pair,
)
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_EXPECTED_TOOL_COUNT = 8
_EXPECTED_GHIDRA_FUNCTION_COUNT = 17


def test_adversarial_benchmark_reports_every_tool_slot() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    tools = report["tools"]
    expect(
        len(tools) == _EXPECTED_TOOL_COUNT
        and {item["tool"] for item in tools} >= {"radare2", "angr", "unicorn", "triton"}
        and all(item["tool"] != "binary-ninja" for item in tools)
    )


def test_adversarial_benchmark_marks_missing_tools_explicitly() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    statuses = {item["tool"]: item["status"] for item in report["tools"]}
    expect(statuses["ida-pro"] == "unavailable" or statuses["ida-pro"] == "completed")


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

    expect(report["sample_count"] == 1)
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
            "samples": 1,
            "unsupported_functions": 0,
        }
    )


def test_adversarial_benchmark_parses_ghidra_function_count_marker() -> None:
    expect(_parse_ghidra_function_count("INFO R2MORPH_FUNCTION_COUNT=sample=17") == _EXPECTED_GHIDRA_FUNCTION_COUNT)


def test_adversarial_benchmark_parses_ghidra_function_counts_by_program() -> None:
    expect(
        _parse_ghidra_function_counts("R2MORPH_FUNCTION_COUNT=one=2\nR2MORPH_FUNCTION_COUNT=two=3")
        == {"one": 2, "two": 3}
    )
