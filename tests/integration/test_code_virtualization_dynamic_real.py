"""Regression coverage for ELF images carrying a dynamic-loader segment."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_dynamic_x86_64"
_EXPECTED_EXIT_CODE = 45


def test_virtualized_elf_with_dynamic_loader_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)
