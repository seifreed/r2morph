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
        "imul $1, %%rax\n"
        "neg %%rax\n"
        "neg %%rax\n"
        "not %%rax\n"
        "not %%rax\n"
        "cmp %%rax, %%rax\n"
        "sete %%cl\n"
        "movzx %%cl, %%ecx\n"
        "sub %%rcx, %%rax\n"
        "add $1, %%rax\n"
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

_STRUCTURED_SOURCE = r"""
__attribute__((noinline)) static long dispatch(long value) {
    long total = 0;
    for (long index = 0; index < 6; ++index) {
        switch ((value + index) & 3) {
        case 0:
            total += value + index;
            break;
        case 1:
            total -= value - index;
            break;
        case 2:
            total ^= value << 1;
            break;
        default:
            total = (total << 1) + value;
            break;
        }
    }
    return total;
}

int main() {
    return dispatch(19) == 139 ? 42 : 1;
}
"""

_FLOATING_POINT_SOURCE = r"""
__attribute__((noinline)) static double compute(double value) {
    volatile double scale = 1.5;
    volatile double bias = 2.25;
    return value * scale + bias;
}

int main(void) {
    volatile double result = compute(3.0);
    return result == 6.75 ? 42 : 1;
}
"""

_SIMD_SOURCE = r"""
#include <emmintrin.h>

__attribute__((noinline)) static int compute(int value) {
    __m128i packed = _mm_set_epi32(value + 3, value + 2, value + 1, value);
    packed = _mm_add_epi32(packed, _mm_set1_epi32(5));
    packed = _mm_xor_si128(packed, _mm_set1_epi32(3));
    int lanes[4];
    _mm_storeu_si128((__m128i *)lanes, packed);
    return lanes[0] + lanes[1] - lanes[2] + lanes[3];
}

int main(void) {
    return compute(7) == 28 ? 42 : 1;
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
        ("gcc", "-O1", ("-fno-pie", "-no-pie")),
        ("gcc", "-O2", ("-fno-pie", "-no-pie")),
        ("gcc", "-O3", ("-fno-pie", "-no-pie")),
        ("gcc", "-Os", ("-fno-pie", "-no-pie")),
        ("gcc", "-O2", ("-fno-pie", "-no-pie", "-fno-omit-frame-pointer")),
        ("gcc", "-O2", ("-fPIE", "-pie")),
        ("gcc", "-O2", ("-fno-pie", "-no-pie", "-s")),
        ("clang", "-O2", ("-fno-pie", "-no-pie")),
    ),
    ids=(
        "gcc-o0",
        "gcc-o1",
        "gcc-o2",
        "gcc-o3",
        "gcc-os",
        "gcc-frame-pointer-o2",
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


@pytest.mark.parametrize(
    ("compiler", "optimization"),
    (
        ("g++", "-O0"),
        ("g++", "-O2"),
        ("g++", "-O3"),
        ("g++", "-Os"),
        ("clang++", "-O2"),
    ),
    ids=("gxx-o0", "gxx-o2", "gxx-o3", "gxx-os", "clangxx-o2"),
)
def test_virtualized_compiler_generated_control_flow_preserves_native_result(
    tmp_path: Path, compiler: str, optimization: str
) -> None:
    source = tmp_path / "structured.cpp"
    original = tmp_path / "structured_original"
    mutated = tmp_path / "structured_mutated"
    source.write_text(_STRUCTURED_SOURCE)

    compile_result = run_command(
        [
            compiler,
            "-std=c++17",
            optimization,
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
    expect(compile_result.returncode == 0, "failed to compile the structured C++ fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260908}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"structured C++ fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        "structured C++ control flow changed native behavior: "
        f"original={original_result.returncode}, mutated={mutated_result.returncode}, {stats=}",
    )


@pytest.mark.parametrize(
    ("compiler", "optimization"),
    (("gcc", "-O0"), ("gcc", "-O2"), ("clang", "-O2")),
    ids=("gcc-o0", "gcc-o2", "clang-o2"),
)
def test_virtualized_compiler_generated_floating_point_preserves_native_result(
    tmp_path: Path, compiler: str, optimization: str
) -> None:
    source = tmp_path / "floating_point.c"
    original = tmp_path / "floating_point_original"
    mutated = tmp_path / "floating_point_mutated"
    source.write_text(_FLOATING_POINT_SOURCE, encoding="utf-8")

    compile_result = run_command(
        [
            compiler,
            optimization,
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
    expect(compile_result.returncode == 0, "failed to compile the floating-point fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 2, "seed": 20260909}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"floating-point fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        "floating-point semantics changed after virtualization: "
        f"original={original_result.returncode}, mutated={mutated_result.returncode}, {stats=}",
    )


@pytest.mark.parametrize(
    ("compiler", "optimization"),
    (("gcc", "-O2"), ("clang", "-O2")),
    ids=("gcc-o2", "clang-o2"),
)
def test_virtualized_compiler_generated_sse2_preserves_native_result(
    tmp_path: Path, compiler: str, optimization: str
) -> None:
    source = tmp_path / "sse2.c"
    original = tmp_path / "sse2_original"
    mutated = tmp_path / "sse2_mutated"
    source.write_text(_SIMD_SOURCE, encoding="utf-8")

    compile_result = run_command(
        [
            compiler,
            optimization,
            "-msse2",
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
    expect(compile_result.returncode == 0, "failed to compile the SSE2 fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 2, "seed": 20260910}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"SSE2 fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        "SSE2 semantics changed after virtualization: "
        f"original={original_result.returncode}, mutated={mutated_result.returncode}, {stats=}",
    )
