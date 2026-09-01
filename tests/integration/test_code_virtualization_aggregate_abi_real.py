"""Real ELF regressions for mixed and indirect System V aggregate returns."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 46

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not supports_native_elf_x86_64(),
        reason="native ELF x86-64 execution requires Linux amd64",
    ),
]


def test_virtualized_elf_preserves_mixed_and_sret_aggregate_abi(tmp_path: Path) -> None:
    source = tmp_path / "aggregate_abi.c"
    executable = tmp_path / "aggregate_abi"
    source.write_text(
        r"""
typedef struct {
    double floating;
    long integer;
} Mixed;

typedef struct {
    long first;
    long second;
    long third;
} Triple;

__attribute__((noinline)) static Mixed make_mixed(double value, long integer) {
    Mixed result = {value + 0.5, integer + 7};
    return result;
}

__attribute__((noinline)) static Triple make_triple(long value) {
    Triple result = {value, value + 1, value + 2};
    return result;
}

__attribute__((noinline)) static long consume(Mixed mixed, Triple triple) {
    return (long)(mixed.floating * 2.0) + mixed.integer + triple.first + triple.second + triple.third;
}

int main(void) {
    Mixed mixed = make_mixed(10.0, 3);
    Triple triple = make_triple(4);
    return consume(mixed, triple) == 46 ? 46 : 1;
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            "-fcf-protection=none",
            source,
            "-o",
            executable,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the aggregate ABI fixture")

    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260907}).apply(binary)
        binary.save()

    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"aggregate ABI fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"aggregate ABI result changed: original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
