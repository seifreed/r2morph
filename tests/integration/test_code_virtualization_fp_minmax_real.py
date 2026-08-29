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
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 4

_SOURCE = r"""
__attribute__((noinline)) static double scalar_minmax(double left, double right) {
    double result = left;
    __asm__ volatile(
        "minsd %1, %0\n\t"
        "maxsd %2, %0"
        : "+x"(result)
        : "m"(right), "x"(left));
    return result;
}

__attribute__((noinline)) static float scalar_single(float left, float right) {
    float result = left;
    __asm__ volatile("minss %1, %0" : "+x"(result) : "x"(right));
    __asm__ volatile("maxss %1, %0" : "+x"(result) : "x"(left));
    return result;
}

int main(void) {
    double result = scalar_minmax(3.0, 8.0);
    float single = scalar_single(2.0f, 7.0f);
    return result == 8.0 && single == 7.0f ? 42 : 1;
}
"""


def test_virtualized_scalar_minmax_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native SSE execution requires an x86-64 host")

    source = tmp_path / "minmax.c"
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
    expect(compile_result.returncode == 0, "failed to compile the native min/max fixture")

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
        f"min/max virtualization changed the result: {stats=}",
    )
