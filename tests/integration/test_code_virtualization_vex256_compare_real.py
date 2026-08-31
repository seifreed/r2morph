"""Real ELF regression coverage for VEX.256 integer comparisons."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 42
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 2

_SOURCE = r"""
#include <immintrin.h>
#include <stdint.h>

__attribute__((noinline)) static __m256i compare_bytes(__m256i left, __m256i right) {
    return _mm256_cmpeq_epi8(left, right);
}

__attribute__((noinline)) static __m256i compare_words(__m256i left, __m256i right) {
    return _mm256_cmpgt_epi16(left, right);
}

int main(void) {
    const int8_t left_bytes[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    const int8_t right_bytes[32] = {0, 9, 2, 9, 4, 9, 6, 9, 8, 9, 10, 9, 12, 9, 14, 9,
                                    16, 9, 18, 9, 20, 9, 22, 9, 24, 9, 26, 9, 28, 9, 30, 9};
    const int16_t left_words[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const int16_t right_words[16] = {0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17};
    int8_t byte_result[32];
    int16_t word_result[16];
    const __m256i bytes = compare_bytes(_mm256_loadu_si256((const __m256i *)left_bytes),
                                        _mm256_loadu_si256((const __m256i *)right_bytes));
    const __m256i words = compare_words(_mm256_loadu_si256((const __m256i *)left_words),
                                        _mm256_loadu_si256((const __m256i *)right_words));
    _mm256_storeu_si256((__m256i *)byte_result, bytes);
    _mm256_storeu_si256((__m256i *)word_result, words);
    return byte_result[0] == -1 && byte_result[1] == 0 && byte_result[2] == -1
            && byte_result[30] == -1 && byte_result[31] == 0
            && word_result[0] == -1 && word_result[1] == 0 && word_result[2] == -1
            && word_result[14] == -1 && word_result[15] == 0
        ? 42
        : 1;
}
"""


def test_virtualized_vex256_integer_comparisons_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex256_compare.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx2",
            "-mno-vzeroupper",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 comparison fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260843}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 integer comparisons returned original={original_result.returncode}, "
        f"transformed={transformed_result.returncode}: {stats=}",
    )
