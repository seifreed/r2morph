"""Real regression for VEX.128 packed arithmetic virtualization."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_x86_64"
_EXPECTED_EXIT_CODE = 42
_EXPECTED_VIRTUALIZED_INSTRUCTIONS = 2


def _mutate_fixture(tmp_path: Path) -> tuple[Path, int]:
    mutated = tmp_path / "mutated_vex128"
    shutil.copy(_FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return mutated, int(stats["total_instructions"])


def test_vex128_virtualization_clears_destination_upper_half_and_preserves_lanes(tmp_path: Path) -> None:
    _mutated, instructions_virtualized = _mutate_fixture(tmp_path)
    expect(instructions_virtualized == _EXPECTED_VIRTUALIZED_INSTRUCTIONS)


def test_vex128_mutation_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX execution requires an x86-64 host")
    mutated, _instructions_virtualized = _mutate_fixture(tmp_path)
    result = run_command([mutated])
    expect(result.returncode == _EXPECTED_EXIT_CODE)
