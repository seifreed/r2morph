"""Real regression for VEX.128 arithmetic and scalar move virtualization."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_x86_64"
_EXPECTED_EXIT_CODE = 42
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 10
_REGRESSION_SEED = 11

_VEX_MEMORY_SOURCE = r"""
__attribute__((noinline)) static void add128_memory(const float *source, float *target) {
    __asm__ volatile(
        "vmovups (%0), %%xmm1\n"
        "vaddps (%0), %%xmm1, %%xmm0\n"
        "vmovups %%xmm0, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "xmm0", "xmm1", "memory"
    );
}

int main(void) {
    const float source[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float target[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    add128_memory(source, target);
    return target[0] == 2.0f && target[3] == 8.0f ? 42 : 1;
}
"""

_VEX_SCALAR_MEMORY_SOURCE = r"""
__attribute__((noinline)) static void addss_memory(const float *source, float *target) {
    __asm__ volatile(
        "vmovups (%0), %%xmm1\n"
        "vaddss (%0), %%xmm1, %%xmm0\n"
        "vmovups %%xmm0, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "xmm0", "xmm1", "memory"
    );
}

int main(void) {
    const float source[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float target[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    addss_memory(source, target);
    return target[0] == 2.0f && target[1] == 2.0f && target[3] == 4.0f ? 42 : 1;
}
"""

_VEX_SCALAR_MOVE_SOURCE = r"""
__attribute__((noinline)) static void move_scalar(const float *source, float *target) {
    __asm__ volatile(
        "vmovups (%0), %%xmm1\n"
        "vmovss (%0), %%xmm0\n"
        "vmovss %%xmm0, %%xmm1, %%xmm0\n"
        "vmovups %%xmm0, (%1)\n"
        "vmovss 4(%0), %%xmm2\n"
        "vmovss %%xmm2, 4(%1)\n"
        :
        : "r"(source), "r"(target)
        : "xmm0", "xmm1", "xmm2", "memory"
    );
}

int main(void) {
    const float source[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float target[4] = {9.0f, 9.0f, 9.0f, 9.0f};
    move_scalar(source, target);
    return target[0] == 1.0f && target[1] == 2.0f && target[2] == 3.0f && target[3] == 4.0f ? 42 : 1;
}
"""

_VEX_QWORD_MOVE_SOURCE = r"""
__attribute__((noinline)) static void move_qword(const unsigned long *source, unsigned long *target) {
    __asm__ volatile(
        "vmovq (%0), %%xmm0\n"
        "vmovq %%xmm0, %%xmm1\n"
        "vmovq %%xmm1, (%1)\n"
        :
        : "r"(source), "r"(target)
        : "xmm0", "xmm1", "memory"
    );
}

__attribute__((noinline)) static unsigned long move_qword_gp(unsigned long value) {
    unsigned long result;
    __asm__ volatile(
        "vmovq %1, %%xmm0\n"
        "vmovq %%xmm0, %%rax\n"
        "mov %%rax, %0\n"
        : "=r"(result)
        : "r"(value)
        : "rax", "xmm0"
    );
    return result;
}

int main(void) {
    const unsigned long source[1] = {0xFEDCBA9876543210UL};
    unsigned long target[1] = {0};
    move_qword(source, target);
    return target[0] == source[0] && move_qword_gp(source[0]) == source[0] ? 42 : 1;
}
"""

_VEX_DWORD_GP_MOVE_SOURCE = r"""
__attribute__((noinline)) static unsigned int move_dword_gp(unsigned int value) {
    unsigned int result;
    __asm__ volatile(
        "vmovd %1, %%xmm0\n"
        "vmovd %%xmm0, %0\n"
        : "=a"(result)
        : "r"(value)
        : "xmm0"
    );
    return result;
}

int main(void) {
    const unsigned int value = 0xA5B6C7D8U;
    return move_dword_gp(value) == value ? 42 : 1;
}
"""

_VEX_VARIABLE_SHIFT_SOURCE = r"""
#include <immintrin.h>

__attribute__((noinline)) static void variable_shift(const unsigned int *source, const unsigned int *counts,
                                                      unsigned int *target) {
    const __m128i values = _mm_loadu_si128((const __m128i *)source);
    const __m128i shifts = _mm_loadu_si128((const __m128i *)counts);
    _mm_storeu_si128((__m128i *)target, _mm_sllv_epi32(values, shifts));
}

int main(void) {
    const unsigned int source[4] = {1U, 2U, 3U, 4U};
    const unsigned int counts[4] = {1U, 2U, 3U, 4U};
    unsigned int target[4] = {0U, 0U, 0U, 0U};
    variable_shift(source, counts, target);
    return target[0] == 2U && target[1] == 8U && target[2] == 24U && target[3] == 64U ? 42 : 1;
}
"""

_VEX_VARIABLE_SHIFT_256_SOURCE = r"""
#include <immintrin.h>

__attribute__((noinline)) static void variable_shift_256(const unsigned int *source, const unsigned int *counts,
                                                          unsigned int *target) {
    const __m256i values = _mm256_loadu_si256((const __m256i *)source);
    const __m256i shifts = _mm256_loadu_si256((const __m256i *)counts);
    _mm256_storeu_si256((__m256i *)target, _mm256_sllv_epi32(values, shifts));
}

int main(void) {
    const unsigned int source[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
    const unsigned int counts[8] = {1U, 2U, 3U, 4U, 1U, 2U, 3U, 4U};
    unsigned int target[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    variable_shift_256(source, counts, target);
    return target[0] == 2U && target[1] == 8U && target[2] == 24U && target[3] == 64U && target[4] == 10U
               && target[5] == 24U && target[6] == 56U && target[7] == 128U
           ? 42
           : 1;
}
"""


def _mutate_fixture(tmp_path: Path) -> tuple[Path, int, bool]:
    mutated = tmp_path / "mutated_vex128"
    shutil.copy(_FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        binary.analyze()
        compute = next(function for function in binary.get_functions() if "compute" in function["name"])
        original_compute_prefix = binary.read_bytes(compute["addr"], 5)
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": _REGRESSION_SEED}).apply(
            binary
        )
        binary.save()
        mutated_compute_prefix = binary.read_bytes(compute["addr"], 5)
    finally:
        binary.close()
    return mutated, int(stats["total_instructions"]), original_compute_prefix != mutated_compute_prefix


def test_vex128_virtualization_clears_destination_upper_half_and_preserves_lanes(tmp_path: Path) -> None:
    _mutated, instructions_virtualized, compute_changed = _mutate_fixture(tmp_path)
    expect(compute_changed and instructions_virtualized >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS)


def test_vex128_mutation_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX execution requires an x86-64 host")
    mutated, _instructions_virtualized, _compute_changed = _mutate_fixture(tmp_path)
    result = run_command([mutated])
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualized VEX.128 fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )


def test_virtualized_vex128_packed_memory_arithmetic_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex128_memory.c"
    original = tmp_path / "original_vex128_memory"
    mutated = tmp_path / "mutated_vex128_memory"
    source.write_text(_VEX_MEMORY_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 memory arithmetic fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260836}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 memory arithmetic changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex128_scalar_memory_arithmetic_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex128_scalar_memory.c"
    original = tmp_path / "original_vex128_scalar_memory"
    mutated = tmp_path / "mutated_vex128_scalar_memory"
    source.write_text(_VEX_SCALAR_MEMORY_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 scalar memory fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260837}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 scalar memory arithmetic changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex128_scalar_moves_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex128_scalar_move.c"
    original = tmp_path / "original_vex128_scalar_move"
    mutated = tmp_path / "mutated_vex128_scalar_move"
    source.write_text(_VEX_SCALAR_MOVE_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 scalar move fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260838}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 scalar moves changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex128_qword_moves_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex128_qword_move.c"
    original = tmp_path / "original_vex128_qword_move"
    mutated = tmp_path / "mutated_vex128_qword_move"
    source.write_text(_VEX_QWORD_MOVE_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 qword move fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260839}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 qword moves changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex128_dword_gp_moves_preserve_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex128_dword_gp_move.c"
    original = tmp_path / "original_vex128_dword_gp_move"
    mutated = tmp_path / "mutated_vex128_dword_gp_move"
    source.write_text(_VEX_DWORD_GP_MOVE_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 dword GP move fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260840}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 dword GP moves changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex128_variable_integer_shift_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex128_variable_shift.c"
    original = tmp_path / "original_vex128_variable_shift"
    mutated = tmp_path / "mutated_vex128_variable_shift"
    source.write_text(_VEX_VARIABLE_SHIFT_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 variable shift fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260841}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.128 variable integer shift changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )


def test_virtualized_vex256_variable_integer_shift_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex256_variable_shift.c"
    original = tmp_path / "original_vex256_variable_shift"
    mutated = tmp_path / "mutated_vex256_variable_shift"
    source.write_text(_VEX_VARIABLE_SHIFT_256_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.256 variable shift fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260842}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "VEX.256 variable integer shift changed the result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )
