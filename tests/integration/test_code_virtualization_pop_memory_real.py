"""Real regression for memory-backed pop virtualization."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_popmem_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_pop_memory_virtualization_preserves_base_indexed_and_rip_execution(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_popmem"
    shutil.copy(_FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(
        stats["functions_virtualized"] >= 1
        and emulate_exit_code(_FIXTURE) == emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE
    )
