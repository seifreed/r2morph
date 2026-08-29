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
typedef double vector_double __attribute__((vector_size(16)));

__attribute__((noinline)) static double scalar_root(double value) {
    double result;
    __asm__ volatile("sqrtsd %1, %0" : "=x"(result) : "x"(value));
    return result;
}

__attribute__((noinline)) static vector_double packed_root(vector_double value) {
    vector_double result;
    __asm__ volatile("sqrtpd %1, %0" : "=x"(result) : "x"(value));
    return result;
}

int main(void) {
    vector_double value = {16.0, 25.0};
    vector_double result = packed_root(value);
    return scalar_root(81.0) == 9.0 && result[0] == 4.0 && result[1] == 5.0 ? 42 : 1;
}
"""


def test_virtualized_scalar_and_packed_sqrt_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native SSE execution requires an x86-64 host")

    source = tmp_path / "sqrt.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the native sqrt fixture")

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
        f"sqrt virtualization changed the result: {stats=}",
    )
