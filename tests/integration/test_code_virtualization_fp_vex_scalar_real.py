"""Real regression for scalar VEX.128 FP arithmetic."""

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
typedef float vector_float __attribute__((vector_size(16)));
typedef double vector_double __attribute__((vector_size(16)));

__attribute__((noinline)) vector_float add_single(vector_float left, vector_float right) {
    vector_float result;
    result = left;
    __asm__ volatile("vaddss %2, %1, %0" : "+x"(result) : "x"(left), "x"(right));
    return result;
}

__attribute__((noinline)) vector_double add_double(vector_double left, vector_double right) {
    vector_double result;
    result = left;
    __asm__ volatile("vaddsd %2, %1, %0" : "+x"(result) : "x"(left), "x"(right));
    return result;
}

int main(void) {
    vector_float single = add_single((vector_float){20.0f, 5.0f, 7.0f, 9.0f},
                                     (vector_float){22.0f, 37.0f, 3.0f, 4.0f});
    vector_double double_value = add_double((vector_double){20.0, 5.0}, (vector_double){22.0, 37.0});
    return single[0] == 42.0f && single[1] == 5.0f && single[2] == 7.0f && single[3] == 9.0f
        && double_value[0] == 42.0 && double_value[1] == 5.0
        ? 42
        : 1;
}
"""


def test_virtualized_vex_scalar_arithmetic_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex_scalar.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx",
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
    expect(compile_result.returncode == 0, "failed to compile the scalar VEX fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260829}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"scalar VEX virtualization changed the result: {stats=}",
    )
