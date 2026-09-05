"""Real-ELF regression coverage for flags saved across an ordinary VM region."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.conftest import _compile_elf_x86_64_binary
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 42

_SOURCE = r"""
.intel_syntax noprefix
.global _start
.text
_start:
    mov eax, 7
    cmp eax, 7
    pushfq
    add eax, 1
    popfq
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 97
done:
    mov eax, 60
    syscall
"""


def test_virtualized_flag_stack_preserves_saved_flags_in_ordinary_region(tmp_path: Path) -> None:
    original = _compile_elf_x86_64_binary(tmp_path, "flag_stack", _SOURCE)

    mutated = tmp_path / "flag_stack_mutated"
    mutated.write_bytes(original.read_bytes())
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260905}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(original) == emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
