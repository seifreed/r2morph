"""Real ELF regression coverage for rotates through carry."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_carry_rotate_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_virtualized_carry_rotates_preserve_results_and_flags(tmp_path: Path) -> None:
    original = tmp_path / "original-carry-rotate"
    mutated = tmp_path / "mutated-carry-rotate"
    shutil.copy(_FIXTURE, original)
    shutil.copy(_FIXTURE, mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(original) == emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
