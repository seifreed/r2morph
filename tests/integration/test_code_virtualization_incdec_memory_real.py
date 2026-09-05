"""Real-ELF regression coverage for memory ``inc``/``dec`` semantics."""

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
.section .data
.align 4
counter:
    .long 0xffffffff
.text
_start:
    lea rbx, [rip + counter]
    stc
    inc dword ptr [rbx]
    jc carry_preserved
    jmp bad
carry_preserved:
    cmp dword ptr [rbx], 0
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 97
done:
    mov eax, 60
    syscall
"""


def test_virtualized_memory_inc_preserves_value_and_carry(tmp_path: Path) -> None:
    original = _compile_elf_x86_64_binary(tmp_path, "inc_memory", _SOURCE)
    mutated = tmp_path / "inc_memory_mutated"
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
