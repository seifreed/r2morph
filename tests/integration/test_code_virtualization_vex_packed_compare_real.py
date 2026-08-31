"""Native regression coverage for VEX packed floating-point comparisons."""

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

_SOURCE = r"""
#include <immintrin.h>

__attribute__((noinline)) static __m256 compare_float(__m256 left, __m256 right) {
    return _mm256_cmp_ps(left, right, _CMP_EQ_OQ);
}

__attribute__((noinline)) static __m256d compare_double(__m256d left, __m256d right) {
    return _mm256_cmp_pd(left, right, _CMP_GT_OQ);
}

int main(void) {
    volatile float float_left_data[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    volatile float float_right_data[8] = {1.0f, 0.0f, 3.0f, 9.0f, 5.0f, 0.0f, 7.0f, 10.0f};
    volatile double double_left_data[4] = {1.0, 2.0, 3.0, 4.0};
    volatile double double_right_data[4] = {0.0, 9.0, 2.0, 9.0};
    const __m256 float_result = compare_float(_mm256_loadu_ps((const float *)float_left_data),
                                               _mm256_loadu_ps((const float *)float_right_data));
    const __m256d double_result = compare_double(_mm256_loadu_pd((const double *)double_left_data),
                                                  _mm256_loadu_pd((const double *)double_right_data));
    return _mm256_movemask_ps(float_result) == 0x55 && _mm256_movemask_pd(double_result) == 0x5
        ? 42
        : 1;
}
"""


def test_virtualized_vex_packed_float_comparisons_preserve_masks(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex_packed_compare.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx",
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
    expect(compile_result.returncode == 0, "failed to compile the packed VEX compare fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260902}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"packed VEX compare fixture was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"packed VEX compare masks changed: original={original_result.returncode}, "
        f"transformed={transformed_result.returncode}, {stats=}",
    )
