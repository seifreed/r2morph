"""Real ELF regression for virtualizing ``push rsp``."""

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
.intel_syntax noprefix
.global _start
.type _start, @function
.text
_start:
    push rsp
    pop rax
    mov edi, 42
    mov eax, 60
    syscall
"""


def _virtualize(source: Path, destination: Path) -> dict[str, object]:
    shutil.copyfile(source, destination)
    binary = Binary(destination, writable=True)
    binary.open()
    try:
        pass_ = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260919})
        stats = pass_.run(binary)
        binary.save()
    finally:
        binary.close()
    return stats


def test_push_rsp_fixture_original_returns_expected_code(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "push_rsp_fixture", _SOURCE)

    expect(emulate_exit_code(fixture) == _EXPECTED_EXIT_CODE)


def test_push_rsp_virtualization_records_instruction(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "push_rsp_fixture", _SOURCE)
    mutated = tmp_path / "mutated_push_rsp"
    stats = _virtualize(fixture, mutated)
    records = stats.get("mutations", [])
    affected = {
        mnemonic
        for record in records
        for mnemonic in record.get("metadata", {}).get("affected_instruction_mnemonics", [])
    }

    expect("push" in affected)


def test_push_rsp_virtualization_preserves_code(tmp_path: Path) -> None:
    fixture = _compile_elf_x86_64_binary(tmp_path, "push_rsp_fixture", _SOURCE)
    mutated = tmp_path / "mutated_push_rsp"
    _virtualize(fixture, mutated)

    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
