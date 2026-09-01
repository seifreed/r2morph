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
_EXPECTED_MEMORY_NOT_EXIT_CODE = 42
_EXPECTED_MEMORY_BT_EXIT_CODE = 42
_EXPECTED_MEMORY_DIV_EXIT_CODE = 42

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


def test_virtualized_memory_not_preserves_all_widths(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86 memory not requires an x86-64 host")

    source = tmp_path / "memory_not.c"
    original = tmp_path / "original_not"
    mutated = tmp_path / "mutated_not"
    source.write_text(r"""
#include <stdint.h>

__attribute__((noinline)) static int complement_memory(
    uint8_t *byte_value, uint16_t *word_value, uint32_t *dword_value, uint64_t *qword_value
) {
    __asm__ volatile(
        "notb (%0)\n"
        "notw (%1)\n"
        "notl (%2)\n"
        "notq (%3)\n"
        :
        : "r"(byte_value), "r"(word_value), "r"(dword_value), "r"(qword_value)
        : "memory");
    return *byte_value == 0xf0 && *word_value == 0xff0f
        && *dword_value == 0xf0f0f0f0U && *qword_value == 0xf0f0f0f0f0f0f0f0ULL ? 42 : 1;
}

int main(void) {
    uint8_t byte_value = 0x0f;
    uint16_t word_value = 0x00f0;
    uint32_t dword_value = 0x0f0f0f0f;
    uint64_t qword_value = 0x0f0f0f0f0f0f0f0fULL;
    return complement_memory(&byte_value, &word_value, &dword_value, &qword_value);
}
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
    expect(compile_result.returncode == 0, "failed to compile memory not fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260901}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_MEMORY_NOT_EXIT_CODE,
        f"memory not changed the result: {stats=}",
    )


def test_virtualized_memory_bt_preserves_immediate_and_register_bits(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86 memory bt requires an x86-64 host")

    source = tmp_path / "memory_bt.c"
    original = tmp_path / "original_bt"
    mutated = tmp_path / "mutated_bt"
    source.write_text(r"""
#include <stdint.h>

__attribute__((noinline)) static int test_memory_bits(uint32_t *word, uint64_t *wide) {
    uint8_t immediate_bit = 0;
    uint8_t register_bit = 0;
    uint64_t index = 1;
    __asm__ volatile(
        "btl $3, (%[word])\n"
        "setc %b[immediate]\n"
        "btq %[index], (%[wide])\n"
        "setc %b[reg_bit]\n"
        : [immediate] "=&r" (immediate_bit), [reg_bit] "=&r" (register_bit)
        : [word] "r" (word), [wide] "r" (wide), [index] "r" (index)
        : "cc", "memory");
    return immediate_bit == 1 && register_bit == 1 ? 42 : 1;
}

int main(void) {
    uint32_t word = 8;
    uint64_t wide = 2;
    return test_memory_bits(&word, &wide);
}
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
    expect(compile_result.returncode == 0, "failed to compile memory bt fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260902}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_MEMORY_BT_EXIT_CODE,
        f"memory bt changed the result: {original_result.returncode=}, {transformed_result.returncode=}, {stats=}",
    )


def test_virtualized_memory_div_preserves_unsigned_and_signed_results(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86 memory div requires an x86-64 host")

    source = tmp_path / "memory_div.c"
    original = tmp_path / "original_div"
    mutated = tmp_path / "mutated_div"
    source.write_text(r"""
#include <stdint.h>

__attribute__((noinline)) static int divide_memory(uint32_t *unsigned_divisor, int32_t *signed_divisor) {
    uint32_t unsigned_quotient = 0;
    uint32_t unsigned_remainder = 0;
    int32_t signed_quotient = 0;
    int32_t signed_remainder = 0;
    __asm__ volatile(
        "movl $100, %%eax\n"
        "xorl %%edx, %%edx\n"
        "divl (%[unsigned_divisor])\n"
        "movl %%eax, %[unsigned_quotient]\n"
        "movl %%edx, %[unsigned_remainder]\n"
        "movl $-55, %%eax\n"
        "cdq\n"
        "idivl (%[signed_divisor])\n"
        "movl %%eax, %[signed_quotient]\n"
        "movl %%edx, %[signed_remainder]\n"
        : [unsigned_quotient] "=m" (unsigned_quotient),
          [unsigned_remainder] "=m" (unsigned_remainder),
          [signed_quotient] "=m" (signed_quotient),
          [signed_remainder] "=m" (signed_remainder)
        : [unsigned_divisor] "r" (unsigned_divisor),
          [signed_divisor] "r" (signed_divisor)
        : "eax", "edx", "cc", "memory");
    return unsigned_quotient == 14 && unsigned_remainder == 2
        && signed_quotient == -13 && signed_remainder == -3 ? 42 : 1;
}

int main(void) {
    uint32_t unsigned_divisor = 7;
    int32_t signed_divisor = 4;
    return divide_memory(&unsigned_divisor, &signed_divisor);
}
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
    expect(compile_result.returncode == 0, "failed to compile memory div fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260903}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_MEMORY_DIV_EXIT_CODE,
        f"memory div changed the result: {stats=}",
    )
