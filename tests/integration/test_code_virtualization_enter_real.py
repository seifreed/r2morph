"""Real ELF regression for level-zero ``enter`` frame virtualization."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.conftest import _compile_elf_x86_64_binary
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_EXPECTED_EXIT_CODE = 42
_SOURCE = r"""
.global _start
.text
_start:
    enter $32, $0
    mov $42, %edi
    mov $60, %eax
    leave
    syscall
.size _start, .-_start
"""


def _virtualize(source: Path, destination: Path) -> dict[str, object]:
    shutil.copyfile(source, destination)
    binary = Binary(destination, writable=True)
    binary.open()
    try:
        binary.analyze("aa")
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260919}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return stats


def test_enter_fixture_original_returns_expected_code(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "enter_fixture", _SOURCE)

    expect(emulate_exit_code(fixture) == _EXPECTED_EXIT_CODE)


def test_enter_fixture_virtualization_applies(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "enter_fixture", _SOURCE)
    stats = _virtualize(fixture, tmp_path / "mutated_enter")

    expect(stats["functions_virtualized"] >= 1)


def test_enter_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "enter_fixture", _SOURCE)
    mutated = tmp_path / "mutated_enter"
    _virtualize(fixture, mutated)

    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
