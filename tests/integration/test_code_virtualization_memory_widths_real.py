"""Real ELF regression coverage for byte and word memory accesses."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_memwidth_x86_64"
_EXPECTED_EXIT_CODE = 80
_EXPECTED_ARITHMETIC_EXIT_CODE = 42
_EXPECTED_IMMEDIATE_STORE_EXIT_CODE = 77

_BYTE_WORD_ARITHMETIC_SOURCE = r"""
#include <stdint.h>

__attribute__((noinline)) static int mutate_memory(
    uint8_t *bytes, uint16_t *words, uint8_t byte_value, uint16_t word_value
) {
    __asm__ volatile(
        "addb %b2, (%0)\n"
        "addw %w3, (%1)\n"
        "addb (%0), %b2\n"
        "addw (%1), %w3\n"
        : "+r"(bytes), "+r"(words), "+q"(byte_value), "+q"(word_value)
        :
        : "cc", "memory"
    );
    return bytes[0] == 8 && words[0] == 0x120 && byte_value == 11 && word_value == 0x140 ? 42 : 1;
}

int main(void) {
    uint8_t bytes[1] = {5};
    uint16_t words[1] = {0x100};
    return mutate_memory(bytes, words, 3, 0x20);
}
"""

pytestmark = pytest.mark.integration


def _virtualize_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return mutated, stats


def test_memory_width_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_memory_width_fixture_virtualization_applies(tmp_path: Path) -> None:
    _, stats = _virtualize_fixture(tmp_path)
    expect(stats["functions_virtualized"] >= 1)


def test_memory_width_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated, _stats = _virtualize_fixture(tmp_path)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_virtualized_byte_word_memory_arithmetic_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86 memory arithmetic requires an x86-64 host")

    source = tmp_path / "memory_arithmetic.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated_arithmetic"
    source.write_text(_BYTE_WORD_ARITHMETIC_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile byte/word memory arithmetic fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260829}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_ARITHMETIC_EXIT_CODE,
        f"byte/word memory arithmetic changed the result: {stats=}",
    )


def test_virtualized_memory_immediate_stores_preserve_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86 memory stores require an x86-64 host")

    source = tmp_path / "memory_immediate.c"
    original = tmp_path / "original_immediate"
    mutated = tmp_path / "mutated_immediate"
    source.write_text(r"""
#include <stdint.h>

__attribute__((noinline)) static int store_immediates(void) {
    uint8_t byte_value = 0;
    uint16_t word_value = 0;
    uint32_t dword_value = 0;
    uint64_t qword_value = 0;
    __asm__ volatile(
        "movb $0x7, (%0)\n"
        "movw $0x1234, (%1)\n"
        "movl $0x12345678, (%2)\n"
        "movq $0x12345678, (%3)\n"
        :
        : "r"(&byte_value), "r"(&word_value), "r"(&dword_value), "r"(&qword_value)
        : "memory");
    return byte_value == 7 && word_value == 0x1234 && dword_value == 0x12345678
        && qword_value == 0x12345678 ? 77 : 1;
}

int main(void) { return store_immediates(); }
""")
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile immediate memory-store fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260835}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_IMMEDIATE_STORE_EXIT_CODE,
        f"immediate memory stores changed the result: {stats=}",
    )
