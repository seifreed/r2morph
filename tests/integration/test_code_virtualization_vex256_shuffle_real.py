"""Real ELF regression coverage for VEX.256 packed shuffles."""

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
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 1

_SOURCE = r"""
#include <stdint.h>

typedef int32_t vector_int __attribute__((vector_size(32)));

__attribute__((noinline)) static vector_int reverse_lanes(vector_int value) {
    vector_int result;
    __asm__ volatile("vpshufd $0x1b, %1, %0" : "=x"(result) : "x"(value));
    return result;
}

int main(void) {
    const vector_int value = {1, 2, 3, 4, 5, 6, 7, 8};
    const vector_int result = reverse_lanes(value);
    return result[0] == 4 && result[1] == 3 && result[2] == 2 && result[3] == 1
            && result[4] == 8 && result[5] == 7 && result[6] == 6 && result[7] == 5
        ? 42
        : 1;
}
"""

_MEMORY_SOURCE = r"""
#include <stdint.h>

typedef int32_t vector_int __attribute__((vector_size(32)));

__attribute__((noinline)) static vector_int reverse_lanes(const vector_int *value) {
    vector_int result;
    __asm__ volatile("vpshufd $0x1b, (%1), %0" : "=x"(result) : "r"(value) : "memory");
    return result;
}

int main(void) {
    const vector_int value = {1, 2, 3, 4, 5, 6, 7, 8};
    const vector_int result = reverse_lanes(&value);
    return result[0] == 4 && result[1] == 3 && result[2] == 2 && result[3] == 1
            && result[4] == 8 && result[5] == 7 && result[6] == 6 && result[7] == 5
        ? 42
        : 1;
}
"""


def test_virtualized_vex256_shuffle_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex256_shuffle.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx2",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 shuffle fixture")

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
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 shuffle returned original={original_result.returncode}, "
        f"transformed={transformed_result.returncode}: {stats=}",
    )


def test_virtualized_vex256_memory_shuffle_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex256_memory_shuffle.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_MEMORY_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx2",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 memory shuffle fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260903}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 memory shuffle returned original={original_result.returncode}, "
        f"transformed={transformed_result.returncode}: {stats=}",
    )
