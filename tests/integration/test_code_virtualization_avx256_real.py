"""Native regression coverage for VEX.256 packed register operations."""

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
typedef float vector256 __attribute__((vector_size(32)));

__attribute__((noinline)) static vector256 add256(vector256 left, vector256 right) {
    return left + right;
}

int main(void) {
    vector256 left = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    vector256 right = {8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    vector256 result = add256(left, right);
    return result[0] == 9.0f && result[7] == 9.0f ? 42 : 1;
}
"""

_MEMORY_SOURCE = r"""
__attribute__((noinline)) static void copy256(const float *source, float *target) {
    __asm__ volatile(
        "vmovups (%0), %%ymm0\n"
        "vmovups %%ymm0, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "ymm0", "memory"
    );
}

int main(void) {
    float source[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float target[8] = {0};
    copy256(source, target);
    return target[0] == 1.0f && target[7] == 8.0f ? 42 : 1;
}
"""


def test_virtualized_vex_256_packed_add_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex256.c"
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 fixture")

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
    expect(stats["functions_virtualized"] >= 1, f"VEX.256 function was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 virtualization changed the result: {stats=}",
    )


def test_virtualized_vex_256_memory_moves_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex256_memory.c"
    original = tmp_path / "original_memory"
    mutated = tmp_path / "mutated_memory"
    source.write_text(_MEMORY_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 memory fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260830}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX.256 memory function was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 memory virtualization changed the result: {stats=}",
    )
