"""Real regression for VEX.128 packed integer virtualization."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_integer_x86_64"
_EXPECTED_EXIT_CODE = 10
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 10


def _mutate_fixture(destination: Path) -> dict[str, int]:
    shutil.copy(_FIXTURE, destination)
    binary = Binary(destination, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return stats


def test_vex128_integer_fixture_original_returns_expected_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_vex128_integer_fixture_virtualization_applies(tmp_path: Path) -> None:
    stats = _mutate_fixture(tmp_path / "mutated_vex128_integer")

    expect(stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS)


def test_vex128_integer_fixture_virtualization_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX execution requires an x86-64 host")
    mutated = tmp_path / "mutated_vex128_integer"
    _mutate_fixture(mutated)

    result = run_command([mutated])
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualized VEX.128 integer fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )
