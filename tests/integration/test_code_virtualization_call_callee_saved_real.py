"""Real ELF regression for the native-call callee-saved register contract."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_call_callee_saved_x86_64"
_EXPECTED_EXIT_CODE = 79

pytestmark = pytest.mark.integration


def test_callee_saved_fixture_original_observes_expected_registers() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def _virtualize_fixture(source: Path, destination: Path) -> dict[str, int]:
    shutil.copyfile(source, destination)
    binary = Binary(destination, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()

    return stats


def test_virtualized_callee_saved_fixture_applies(tmp_path: Path) -> None:
    stats = _virtualize_fixture(_FIXTURE, tmp_path / "mutated")

    expect(stats["functions_virtualized"] >= 1)


def test_virtualized_callee_saved_fixture_preserves_registers(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated"
    _virtualize_fixture(_FIXTURE, mutated)

    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
