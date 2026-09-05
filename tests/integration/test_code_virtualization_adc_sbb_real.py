"""Real-ELF regression coverage for virtual carry-consuming arithmetic."""

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
    xor eax, eax
    mov ecx, 1
    cmp eax, ecx
    adc eax, 40
    jnc adc_ok
    jmp bad
adc_ok:
    cmp eax, 41
    jne bad
    mov rax, -1
    xor edx, edx
    cmp edx, ecx
    adc rax, rdx
    jc adc64_ok
    jmp bad
adc64_ok:
    cmp rax, 0
    jne bad
    xor eax, eax
    xor edx, edx
    cmp eax, ecx
    sbb eax, edx
    jc sbb_ok
    jmp bad
sbb_ok:
bad:
    mov edi, 97
    cmp eax, -1
    je good
    jmp done
good:
    mov edi, 42
done:
    mov eax, 60
    syscall
"""

_MEMORY_SOURCE = r"""
.intel_syntax noprefix
.global _start
.section .data
.align 4
direct_value:
    .long 1
indexed_value:
    .long 1
.text
_start:
    xor eax, eax
    clc
    adc eax, dword ptr [rip + direct_value]
    jc bad
    cmp eax, 1
    jne bad
    xor ecx, ecx
    mov eax, 2
    stc
    sbb eax, dword ptr [rcx*4 + indexed_value]
    jc bad
    test eax, eax
    jne bad
    mov edi, 42
    jmp done
bad:
    mov edi, 97
done:
    mov eax, 60
    syscall
"""


def test_virtualized_adc_sbb_preserve_incoming_and_result_carry(tmp_path: Path) -> None:
    original = _compile_elf_x86_64_binary(tmp_path, "adc_sbb", _SOURCE)

    mutated = tmp_path / "adc_sbb_mutated"
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


def test_virtualized_memory_adc_sbb_preserve_virtual_carry(tmp_path: Path) -> None:
    original = _compile_elf_x86_64_binary(tmp_path, "adc_sbb_memory", _MEMORY_SOURCE)
    mutated = tmp_path / "adc_sbb_memory_mutated"
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
