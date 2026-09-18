"""Native regression coverage for implicit-memory string virtualization."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 42

_SOURCE = r"""
#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) static int copy_bytes(void) {
    uint8_t source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t destination[8] = {0};
    size_t count = sizeof(source);
    __asm__ volatile(
        "cld\n"
        "rep movsb\n"
        : "+S"(source), "+D"(destination), "+c"(count)
        :
        : "memory");
    return destination[0] + destination[7] + (int)count;
}

int main(void) { return copy_bytes() == 9 ? 42 : 1; }
"""

pytestmark = pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native string virtualization requires Linux x86-64",
)


def test_virtualized_rep_movsb_preserves_native_result(tmp_path: Path) -> None:
    source = tmp_path / "string_copy.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O0",
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
    expect(compile_result.returncode == 0, "failed to compile string instruction fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260918}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"string fixture was not virtualized: {stats=}")
    expect(
        (
            original_result.returncode,
            transformed_result.returncode,
        )
        == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"rep movsb changed the result: {stats=}",
    )
