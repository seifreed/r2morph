"""Real ELF regression coverage for integer packed XMM operations."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_simdint_x86_64"
_ARITHMETIC_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_simdintarith_x86_64"
_WIDE_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_simdwide_x86_64"
_EXTRA_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_simdextra_x86_64"
_EXPECTED_EXIT_CODE = 46
_EXPECTED_ARITHMETIC_EXIT_CODE = 62
_INSERT_EXIT_CODE = 42

pytestmark = pytest.mark.integration


def _virtualize_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return mutated, stats


def test_simd_integer_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_simd_integer_fixture_virtualization_applies(tmp_path: Path) -> None:
    _, stats = _virtualize_fixture(tmp_path)
    expect(stats["functions_virtualized"] >= 1)


def test_simd_integer_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated, _stats = _virtualize_fixture(tmp_path)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_simd_integer_arithmetic_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_ARITHMETIC_FIXTURE) == _EXPECTED_ARITHMETIC_EXIT_CODE)


def test_simd_integer_arithmetic_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-arithmetic"
    shutil.copyfile(_ARITHMETIC_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_ARITHMETIC_EXIT_CODE)


def test_simd_integer_wide_fixture_original_has_an_exit_code() -> None:
    expect(emulate_exit_code(_WIDE_FIXTURE) is not None)


def test_simd_integer_wide_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-wide"
    shutil.copyfile(_WIDE_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == emulate_exit_code(_WIDE_FIXTURE))


def test_simd_integer_extra_fixture_original_has_an_exit_code() -> None:
    expect(emulate_exit_code(_EXTRA_FIXTURE) is not None)


def test_simd_integer_extra_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-extra"
    shutil.copyfile(_EXTRA_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == emulate_exit_code(_EXTRA_FIXTURE))


def test_vpinsrd_with_vmovd_memory_virtualizes_and_preserves_result(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("native VEX.128 SIMD execution requires Linux x86-64")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("the VEX.128 SIMD fixture requires gcc")

    source = tmp_path / "vex-insert.c"
    original = tmp_path / "vex-insert-original"
    mutated = tmp_path / "vex-insert-mutated"
    source.write_text(
        r"""
#include <stdint.h>

int main(void) {
    uint32_t value = 42;
    uint32_t lane;
    __asm__ volatile(
        "vmovd %[memory], %%xmm0\n\t"
        "vpinsrd $1, %[value], %%xmm0, %%xmm0\n\t"
        "vpextrd $1, %%xmm0, %[lane]"
        : [lane] "=r" (lane)
        : [memory] "m" (value), [value] "r" (value)
        : "xmm0");
    return lane == 42 ? 42 : 1;
}
""",
        encoding="utf-8",
    )
    compile_result = run_command(
        [
            compiler,
            "-O1",
            "-mavx",
            "-msse4.1",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 insert fixture")
    expect(run_command([original], timeout=30).returncode == _INSERT_EXIT_CODE)
    shutil.copy2(original, mutated)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        virtualization_pass = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20261120})
        stats = virtualization_pass.apply(binary)
        binary.save()

    affected = {
        mnemonic
        for record in virtualization_pass.get_records()
        for mnemonic in record.metadata.get("affected_instruction_mnemonics", [])
    }
    expect(stats["functions_virtualized"] >= 1 and {"vmovd", "vpinsrd"} <= affected)
    expect(run_command([mutated], timeout=30).returncode == _INSERT_EXIT_CODE)
