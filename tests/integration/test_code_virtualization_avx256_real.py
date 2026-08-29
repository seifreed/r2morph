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

_MEMORY_ARITHMETIC_SOURCE = r"""
__attribute__((noinline)) static void add256_memory(const float *source, float *target) {
    __asm__ volatile(
        "vmovups (%0), %%ymm1\n"
        "vaddps (%0), %%ymm1, %%ymm0\n"
        "vmovups %%ymm0, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "ymm0", "ymm1", "memory"
    );
}

int main(void) {
    float source[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float target[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    add256_memory(source, target);
    return target[0] == 2.0f && target[7] == 16.0f ? 42 : 1;
}
"""

_MEMORY_UNARY_SOURCE = r"""
__attribute__((noinline)) static void sqrt256_memory(const float *source, float *target) {
    __asm__ volatile(
        "vsqrtps (%0), %%ymm0\n"
        "vmovups %%ymm0, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "ymm0", "memory"
    );
}

int main(void) {
    float source[8] = {1.0f, 4.0f, 9.0f, 16.0f, 25.0f, 36.0f, 49.0f, 64.0f};
    float target[8] = {0};
    sqrt256_memory(source, target);
    return target[0] == 1.0f && target[7] == 8.0f ? 42 : 1;
}
"""

_VARIABLE_SHIFT_SOURCE = r"""
#include <stdint.h>

__attribute__((noinline)) static void shift256(
    const uint32_t *values, const uint32_t *counts, uint32_t *target, uint32_t *immediate_target
) {
    __asm__ volatile(
        "vmovdqu (%0), %%ymm1\n"
        "vmovdqu (%1), %%ymm2\n"
        "vpslld %%ymm2, %%ymm1, %%ymm0\n"
        "vmovdqu %%ymm0, (%2)\n"
        "vpsrad $1, %%ymm1, %%ymm0\n"
        "vmovdqu %%ymm0, (%3)\n"
        :
        : "r"(values), "r"(counts), "r"(target), "r"(immediate_target)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
}

int main(void) {
    const uint32_t values[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint32_t counts[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint32_t target[8] = {0};
    int32_t immediate_target[8] = {0};
    shift256(values, counts, target, (uint32_t *)immediate_target);
    return target[0] == 2 && target[7] == 16 && immediate_target[0] == 0 && immediate_target[7] == 4 ? 42 : 1;
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


def test_virtualized_vex_256_variable_shift_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex256_variable_shift.c"
    original = tmp_path / "original_variable_shift"
    mutated = tmp_path / "mutated_variable_shift"
    source.write_text(_VARIABLE_SHIFT_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 variable-shift fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260832}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX.256 variable-shift function was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 variable-shift virtualization changed the result: {stats=}",
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


def test_virtualized_vex_256_memory_arithmetic_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex256_memory_arithmetic.c"
    original = tmp_path / "original_memory_arithmetic"
    mutated = tmp_path / "mutated_memory_arithmetic"
    source.write_text(_MEMORY_ARITHMETIC_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 memory arithmetic fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260831}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX.256 memory arithmetic function was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 memory arithmetic virtualization changed the result: {stats=}",
    )


def test_virtualized_vex_256_memory_unary_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex256_memory_unary.c"
    original = tmp_path / "original_memory_unary"
    mutated = tmp_path / "mutated_memory_unary"
    source.write_text(_MEMORY_UNARY_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 memory unary fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260832}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX.256 memory unary function was not virtualized: {stats=}")
    expect(
        original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX.256 memory unary virtualization changed the result: {stats=}",
    )
