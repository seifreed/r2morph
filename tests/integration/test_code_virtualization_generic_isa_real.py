"""Real ELF coverage for a compiler-generated, out-of-corpus ISA mix."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 42
_EXPECTED_STDOUT = "result=44 slot=22\n"

_SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) static long exercise(long value, long *slot) {
    long result;
    __asm__ volatile(
        "mov %[value], %%rax\n"
        "add $7, %%rax\n"
        "sub $2, %%rax\n"
        "xor $3, %%rax\n"
        "or $8, %%rax\n"
        "and $0xff, %%rax\n"
        "shl $1, %%rax\n"
        "shr $1, %%rax\n"
        "sar $1, %%rax\n"
        "stc\n"
        "adc $1, %%rax\n"
        "clc\n"
        "sbb $2, %%rax\n"
        "rol $7, %%rax\n"
        "ror $7, %%rax\n"
        "mov %%rax, (%[slot])\n"
        "mov (%[slot]), %%rcx\n"
        "add %%rcx, %%rax\n"
        : "=a"(result)
        : [value] "r"(value), [slot] "r"(slot)
        : "rcx", "memory", "cc");
    return result;
}

int main(void) {
    long slot = 0;
    long result = exercise(41, &slot);
    printf("result=%ld slot=%ld\n", result, slot);
    return result == 44 && slot == 22 ? 42 : 1;
}
"""

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not supports_native_elf_x86_64(),
        reason="native ELF x86-64 execution requires Linux amd64",
    ),
]


@pytest.mark.parametrize(
    ("compiler", "optimization", "build_flags"),
    (
        ("gcc", "-O0", ("-fno-pie", "-no-pie")),
        ("gcc", "-O2", ("-fno-pie", "-no-pie")),
        ("gcc", "-O3", ("-fno-pie", "-no-pie")),
        ("gcc", "-Os", ("-fno-pie", "-no-pie")),
        ("gcc", "-O2", ("-fPIE", "-pie")),
        ("gcc", "-O2", ("-fno-pie", "-no-pie", "-s")),
        ("clang", "-O2", ("-fno-pie", "-no-pie")),
    ),
    ids=(
        "gcc-o0",
        "gcc-o2",
        "gcc-o3",
        "gcc-os",
        "gcc-pie-o2",
        "gcc-stripped-o2",
        "clang-o2",
    ),
)
def test_virtualized_compiler_generated_isa_mix_preserves_native_result(
    tmp_path: Path, compiler: str, optimization: str, build_flags: tuple[str, ...]
) -> None:
    source = tmp_path / f"isa_mix_{compiler}_{optimization[1:]}.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)

    compile_result = run_command(
        [
            compiler,
            optimization,
            *build_flags,
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the generic ISA fixture")
    original_result = run_command([original], text=True, timeout=30)
    original.rename(mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 2, "seed": 20260907}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], text=True, timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"generic ISA mix was not virtualized: {stats=}")
    expect(
        (
            original_result.returncode,
            original_result.stdout,
            original_result.stderr,
        )
        == (
            mutated_result.returncode,
            mutated_result.stdout,
            mutated_result.stderr,
        )
        == (_EXPECTED_EXIT_CODE, _EXPECTED_STDOUT, ""),
        f"generic ISA mix changed native behavior: {stats=}",
    )
