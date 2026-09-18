"""Native regression coverage for the implicit xlatb memory operation."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 42

pytestmark = pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native xlat virtualization requires Linux x86-64",
)


def test_virtualized_xlatb_preserves_native_lookup_result(tmp_path: Path) -> None:
    source = tmp_path / "xlat.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(r"""
#include <stdint.h>

__attribute__((noinline)) static int table_lookup(unsigned int value) {
    static const uint8_t table[256] = {[42] = 73};
    unsigned long index = value & 255u;
    const uint8_t *base = table;
    __asm__ volatile("xlatb" : "+a"(index) : "b"(base) : "memory");
    return (int)(uint8_t)index;
}

int main(void) { return table_lookup(42) == 73 ? 42 : 1; }
""")
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
    expect(compile_result.returncode == 0, "failed to compile xlat fixture")
    baseline = run_command([original], timeout=30)
    original.rename(mutated)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260918}).apply(binary)
        binary.save()

    transformed = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"xlat fixture was not virtualized: {stats=}")
    expect((baseline.returncode, transformed.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE))
