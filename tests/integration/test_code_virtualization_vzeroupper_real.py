"""Native regression coverage for VZEROUPPER state semantics."""

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
#include <stdint.h>

__attribute__((noinline)) static int clear_upper(void) {
    const uint32_t input[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t output[8] = {0};
    __asm__ volatile(
        "vmovdqu (%0), %%ymm0\n"
        "vzeroupper\n"
        "vmovdqu %%ymm0, (%1)\n"
        :
        : "r"(input), "r"(output)
        : "ymm0", "memory"
    );
    return output[0] == 1 && output[4] == 0 ? 1 : 0;
}

int main(void) {
    return clear_upper() == 1 ? 42 : 1;
}
"""


_VZEROALL_SOURCE = r"""
#include <stdint.h>

__attribute__((noinline)) static int clear_all(void) {
    const uint32_t input[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t output[8] = {0};
    __asm__ volatile(
        "vmovdqu (%0), %%ymm0\n"
        "vzeroall\n"
        "vmovdqu %%ymm0, (%1)\n"
        :
        : "r"(input), "r"(output)
        : "ymm0", "memory"
    );
    return output[0] == 0 && output[4] == 0 ? 42 : 1;
}

int main(void) {
    return clear_all();
}
"""


def _virtualize_source(tmp_path: Path, source_text: str, name: str) -> tuple[int, int, dict[str, object]]:
    source = tmp_path / f"{name}.c"
    original = tmp_path / f"original-{name}"
    mutated = tmp_path / f"mutated-{name}"
    source.write_text(source_text)
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
    expect(compile_result.returncode == 0, f"failed to compile the {name} fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260830}).apply(binary)
        binary.save()

    transformed_result = run_command([mutated], timeout=30)
    return original_result.returncode, transformed_result.returncode, stats


def test_virtualized_vzeroupper_preserves_low_lanes_and_clears_upper_lanes(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    original_exit, transformed_exit, stats = _virtualize_source(tmp_path, _SOURCE, "vzeroupper")
    expect(stats["functions_virtualized"] >= 1)
    expect(original_exit == transformed_exit == _EXPECTED_EXIT_CODE)


def test_virtualized_vzeroall_clears_all_lanes(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    original_exit, transformed_exit, stats = _virtualize_source(tmp_path, _VZEROALL_SOURCE, "vzeroall")
    expect(stats["functions_virtualized"] >= 1)
    expect(original_exit == transformed_exit == _EXPECTED_EXIT_CODE)
