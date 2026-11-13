"""Regression contracts for bounded adversarial benchmark mutation workers."""

from pathlib import Path

import pytest

from scripts.adversarial_benchmark_constants import _EXPECTED_TOOLS
from scripts.adversarial_benchmark_execution import (
    MutationWorkerTimeoutError,
    _benchmark_passes,
    _protected_copy,
)
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"


def test_adversarial_mutation_timeout_raises_for_real_worker(tmp_path: Path) -> None:
    with pytest.raises(MutationWorkerTimeoutError):
        _protected_copy(_FIXTURE, tmp_path, "AntiDisassembly", timeout_seconds=0.01)


def test_adversarial_mutation_timeout_records_failed_pass(tmp_path: Path) -> None:
    pass_rows, _ = _benchmark_passes(
        _FIXTURE,
        tmp_path,
        ("AntiDisassembly",),
        timeout_seconds=0.01,
    )

    expect(
        pass_rows[0]["error_type"] == "MutationWorkerTimeoutError"
        and str(pass_rows[0].get("detail", "")).startswith("Mutation worker exceeded")
    )


def test_adversarial_mutation_timeout_preserves_every_analyzer_slot(tmp_path: Path) -> None:
    _, tool_rows = _benchmark_passes(
        _FIXTURE,
        tmp_path,
        ("AntiDisassembly",),
        timeout_seconds=0.01,
    )

    expect([row["tool"] for row in tool_rows] == [*_EXPECTED_TOOLS, "custom"])
