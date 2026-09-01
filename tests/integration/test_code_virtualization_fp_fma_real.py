"""Real x86-64 regressions for packed VEX FMA virtualization."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 47
_FMA_SOURCE = r"""
typedef float vector128 __attribute__((vector_size(16)));
typedef float vector256 __attribute__((vector_size(32)));

__attribute__((noinline)) static vector128 fma128(vector128 a, vector128 b, vector128 c) {
    __asm__ volatile("vfmadd231ps %1, %2, %0" : "+x"(a) : "x"(b), "x"(c));
    return a;
}

__attribute__((noinline)) static vector256 fma256(vector256 a, vector256 b, vector256 c) {
    __asm__ volatile("vfmadd231ps %1, %2, %0" : "+v"(a) : "v"(b), "v"(c));
    return a;
}

__attribute__((noinline)) static vector128 fma128_memory(vector128 a, vector128 b, const vector128 *c) {
    __asm__ volatile("vfmadd231ps %1, %2, %0" : "+x"(a) : "x"(b), "m"(*c));
    return a;
}

__attribute__((noinline)) static vector256 fma256_memory(vector256 a, vector256 b, const vector256 *c) {
    __asm__ volatile("vfmadd231ps %1, %2, %0" : "+v"(a) : "v"(b), "m"(*c));
    return a;
}

int main(void) {
    const vector128 a128 = {1.0f, 2.0f, 3.0f, 4.0f};
    const vector128 b128 = {2.0f, 3.0f, 4.0f, 5.0f};
    const vector128 c128 = {10.0f, 20.0f, 30.0f, 40.0f};
    const vector256 a256 = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    const vector256 b256 = {2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f};
    const vector256 c256 = {10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f};
    const vector128 result128 = fma128(a128, b128, c128);
    const vector256 result256 = fma256(a256, b256, c256);
    const vector128 result128_memory = fma128_memory(a128, b128, &c128);
    const vector256 result256_memory = fma256_memory(a256, b256, &c256);
    return result128[0] == 21.0f && result128[3] == 204.0f && result256[0] == 21.0f && result256[7] == 728.0f
               && result128_memory[0] == 21.0f && result128_memory[3] == 204.0f
               && result256_memory[0] == 21.0f && result256_memory[7] == 728.0f
               ? 47
               : 1;
}
"""


def test_virtualized_packed_vex_fma_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native FMA execution requires an x86-64 host")

    source = tmp_path / "packed_fma.c"
    original = tmp_path / "original_packed_fma"
    mutated = tmp_path / "mutated_packed_fma"
    source.write_text(_FMA_SOURCE, encoding="ascii")
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx2",
            "-mfma",
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
    expect(compile_result.returncode == 0, "failed to compile the packed FMA fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260901}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        "packed FMA virtualization changed the native result: "
        f"{stats=}, original={original_result.returncode}, transformed={transformed_result.returncode}",
    )
