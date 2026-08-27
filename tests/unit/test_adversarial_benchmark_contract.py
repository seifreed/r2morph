"""Regression contract for complete analyzer benchmark reporting."""

from pathlib import Path

from scripts.adversarial_benchmark import benchmark_pair
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_EXPECTED_TOOL_COUNT = 9


def test_adversarial_benchmark_reports_every_tool_slot() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    tools = report["tools"]
    expect(len(tools) == _EXPECTED_TOOL_COUNT and {item["tool"] for item in tools} >= {"radare2", "angr", "unicorn"})


def test_adversarial_benchmark_marks_missing_tools_explicitly() -> None:
    report = benchmark_pair(_FIXTURE, _FIXTURE)

    statuses = {item["tool"]: item["status"] for item in report["tools"]}
    expect(statuses["ida-pro"] == "unavailable" or statuses["ida-pro"] == "completed")
