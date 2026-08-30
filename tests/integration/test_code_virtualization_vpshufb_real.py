"""Native regression coverage for VEX byte shuffles."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 42
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 2

_SOURCE = r"""
#include <stdint.h>

typedef uint8_t vector128 __attribute__((vector_size(16)));
typedef uint8_t vector256 __attribute__((vector_size(32)));

__attribute__((noinline)) static vector128 shuffle128(vector128 value, vector128 mask) {
    vector128 result;
    __asm__ volatile("vpshufb %2, %1, %0" : "=x"(result) : "x"(value), "x"(mask));
    return result;
}

__attribute__((noinline)) static vector256 shuffle256(vector256 value, vector256 mask) {
    vector256 result;
    __asm__ volatile("vpshufb %2, %1, %0" : "=x"(result) : "x"(value), "x"(mask));
    return result;
}

int main(void) {
    const vector128 value128 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const vector128 mask128 = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    const vector256 value256 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    const vector256 mask256 = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
                               15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    const vector128 result128 = shuffle128(value128, mask128);
    const vector256 result256 = shuffle256(value256, mask256);
    return result128[0] == 16 && result128[15] == 1
            && result256[0] == 16 && result256[15] == 1
            && result256[16] == 32 && result256[31] == 17
        ? 42
        : 1;
}
"""


def test_virtualized_vpshufb_preserves_128_and_256_bit_results(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("native AVX2 execution requires Linux amd64")

    source = tmp_path / "vpshufb.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O0",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX byte-shuffle fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260830}).apply(binary)

    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX byte-shuffle virtualization changed the result: {stats=}",
    )
