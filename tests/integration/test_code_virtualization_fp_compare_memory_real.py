"""Real ELF regression coverage for scalar FP memory compares."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_fpcmpmem_x86_64"
_EXPECTED_EXIT_CODE = 44

_RIPREL_SOURCE = r"""
static const double threshold = 3.0;

__attribute__((noinline)) static int compare_threshold(double value) {
    return value > threshold ? 42 : 1;
}

int main(void) {
    return compare_threshold(4.0) == 42 ? 0 : 1;
}
"""

_VEX_COMPARE_SOURCE = r"""
static volatile double threshold = 3.0;

__attribute__((noinline)) static int compare_vex_scalar(double value) {
    unsigned char result;
    __asm__ volatile(
        "vucomisd %[memory], %[value]\n"
        "seta %[result]\n"
        : [result] "=a"(result)
        : [memory] "m"(threshold), [value] "x"(value)
        : "cc");
    return result;
}

int main(void) {
    return compare_vex_scalar(4.0) == 1 ? 0 : 1;
}
"""

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


def test_fpcmp_memory_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_fpcmp_memory_fixture_virtualization_applies(tmp_path: Path) -> None:
    _, stats = _virtualize_fixture(tmp_path)
    expect(stats["functions_virtualized"] >= 1)


def test_fpcmp_memory_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated, _stats = _virtualize_fixture(tmp_path)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_fpcmp_riprel_native_fixture_virtualization_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF virtualization requires an x86-64 host")

    source = tmp_path / "fpcmp_riprel.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_RIPREL_SOURCE, encoding="utf-8")
    compile_result = run_command(
        ["gcc", "-O2", "-fno-pie", "-no-pie", source, "-o", original],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the RIP-relative FP compare fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260831}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1 and original_result.returncode == transformed_result.returncode == 0,
        f"RIP-relative FP compare virtualization changed the result: {stats=}",
    )


def test_vex_scalar_fp_compare_native_fixture_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX execution requires an x86-64 host")

    source = tmp_path / "vex_fpcmp.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_VEX_COMPARE_SOURCE, encoding="utf-8")
    compile_result = run_command(
        ["gcc", "-O2", "-mavx", "-fno-pie", "-no-pie", source, "-o", original],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the VEX scalar FP compare fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260831}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1 and original_result.returncode == transformed_result.returncode == 0,
        f"VEX scalar FP compare virtualization changed the result: original={original_result.returncode}, "
        f"transformed={transformed_result.returncode}, {stats=}",
    )
