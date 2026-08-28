"""Real ELF regression coverage for integer 128-bit XMM moves."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_simdmove_x86_64"
_EXPECTED_EXIT_CODE = 42

pytestmark = pytest.mark.integration


def test_simd_move_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_simd_move_fixture_virtualization_preserves_both_qwords(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-simd-move"
    shutil.copyfile(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260830}).apply(binary)
        binary.save()

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
