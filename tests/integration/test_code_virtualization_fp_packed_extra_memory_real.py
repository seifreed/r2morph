"""Native regression for legacy packed SIMD memory-source virtualization."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = pytest.mark.integration
_EXPECTED_EXIT_CODE = 42


def test_virtualized_legacy_packed_memory_source_preserves_result(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("native SSSE3 execution requires Linux amd64")
    if shutil.which("gcc") is None:
        pytest.skip("fixture requires gcc")

    source = tmp_path / "packed_memory.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(r"""
static const unsigned char input[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const unsigned char mask[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

__attribute__((noinline)) static int shuffle_from_memory(void) {
    unsigned char output[16] = {0};
    __asm__ volatile(
        "movdqu (%[input]), %%xmm0\n\t"
        "pshufb (%[mask]), %%xmm0\n\t"
        "movdqu %%xmm0, (%[output])\n\t"
        :
        : [input] "r"(input), [mask] "r"(mask), [output] "r"(output)
        : "xmm0", "memory");
    return output[0] == 16 && output[15] == 1 ? 42 : 1;
}

int main(void) { return shuffle_from_memory(); }
""")
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mssse3",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            "-fcf-protection=none",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the packed memory SIMD fixture")

    shutil.copy2(original, mutated)
    original_result = run_command([original], timeout=30)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260911}).apply(binary)
        binary.save()
    mutated_result = run_command([mutated], timeout=30)

    expect(stats["functions_virtualized"] >= 1, f"packed memory fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"packed memory result changed: original={original_result.returncode}, mutated={mutated_result.returncode}",
    )


def test_virtualized_legacy_horizontal_memory_source_preserves_result(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("native SSSE3 execution requires Linux amd64")
    if shutil.which("gcc") is None:
        pytest.skip("fixture requires gcc")

    source = tmp_path / "horizontal_memory.c"
    original = tmp_path / "original_horizontal"
    mutated = tmp_path / "mutated_horizontal"
    source.write_text(r"""
#include <stdint.h>

static const int16_t left[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const int16_t right[8] = {10, 20, 30, 40, 50, 60, 70, 80};

__attribute__((noinline)) static int horizontal_from_memory(void) {
    int16_t output[8] = {0};
    __asm__ volatile(
        "movdqu (%[left]), %%xmm0\n\t"
        "phaddw (%[right]), %%xmm0\n\t"
        "movdqu %%xmm0, (%[output])\n\t"
        :
        : [left] "r"(left), [right] "r"(right), [output] "r"(output)
        : "xmm0", "memory");
    return output[0] == 3 && output[3] == 15 && output[4] == 30 && output[7] == 150 ? 42 : 1;
}

int main(void) { return horizontal_from_memory(); }
""")
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mssse3",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            "-fcf-protection=none",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the horizontal packed fixture")

    shutil.copy2(original, mutated)
    original_result = run_command([original], timeout=30)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260912}).apply(binary)
        binary.save()
    mutated_result = run_command([mutated], timeout=30)

    expect(stats["functions_virtualized"] >= 1, f"horizontal packed fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"horizontal packed result changed: original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
