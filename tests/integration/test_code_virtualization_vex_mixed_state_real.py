"""Real ELF regression for VEX.128 to VEX.256 state transitions."""

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
#include <stdint.h>

__attribute__((noinline)) static int mixed_state(int selector) {
    const uint32_t input[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t output[8] = {0};
    __asm__ volatile(
        "vmovdqu (%0), %%ymm0\n"
        "vpxor %%ymm1, %%ymm1, %%ymm1\n"
        "vpxor %%xmm0, %%xmm0, %%xmm0\n"
        "vpxor %%ymm0, %%ymm1, %%ymm2\n"
        "vmovdqu %%ymm2, (%1)\n"
        :
        : "r"(input), "r"(output), "r"(selector)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
    return output[0] == 0 && output[4] == 0 && output[7] == 0 ? 42 + selector : 1;
}

int main(int argc, char **argv) {
    return mixed_state(argc > 1 ? 1 : 0);
}
"""


def test_virtualized_vex128_to_vex256_transition_preserves_zeroed_upper_state(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    source = tmp_path / "vex_mixed_state.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the mixed VEX state fixture")

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
        f"mixed VEX state virtualization changed the result: {stats=}",
    )
