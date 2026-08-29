"""Real regression for non-destructive VEX.128 packed FP arithmetic."""

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

__attribute__((noinline)) static vector_float add_vectors(vector_float left, vector_float right) {
    vector_float result;
    __asm__ volatile("vaddps %1, %2, %0" : "=x"(result) : "x"(left), "x"(right));
    return result;
}

int main(void) {
    vector_float left = {20.0f, 5.0f, 7.0f, 9.0f};
    vector_float right = {22.0f, 37.0f, 3.0f, 4.0f};
    vector_float result = add_vectors(left, right);
    return result[0] == 42.0f && result[1] == 42.0f && result[2] == 10.0f && result[3] == 13.0f
        ? 42
        : 1;
}
"""


def test_virtualized_vex_nondestructive_packed_add_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex_nondestructive.c"
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
    expect(compile_result.returncode == 0, "failed to compile the non-destructive VEX fixture")

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
        f"non-destructive VEX virtualization changed the result: {stats=}",
    )
