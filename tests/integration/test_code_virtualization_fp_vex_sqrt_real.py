from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 42
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 2

_SOURCE = r"""
int main(void) {
    float single_input = 16.0f;
    double double_input = 81.0;
    float single_result;
    double double_result;
    __asm__ volatile("vsqrtss %2, %1, %0" : "=x"(single_result) : "x"(single_input), "x"(single_input));
    __asm__ volatile("vsqrtsd %2, %1, %0" : "=x"(double_result) : "x"(double_input), "x"(double_input));
    return single_result == 4.0f && double_result == 9.0 ? 42 : 1;
}
"""

_MEMORY_SOURCE = r"""
int main(void) {
    float single_input = 16.0f;
    double double_input = 81.0;
    float single_result = 1.0f;
    double double_result = 1.0;
    __asm__ volatile("vsqrtss %1, %0, %0" : "+x"(single_result) : "m"(single_input));
    __asm__ volatile("vsqrtsd %1, %0, %0" : "+x"(double_result) : "m"(double_input));
    return single_result == 4.0f && double_result == 9.0 ? 42 : 1;
}
"""


def test_virtualized_vex_scalar_sqrt_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex_sqrt.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx",
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
    expect(compile_result.returncode == 0, "failed to compile the native VEX sqrt fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260829}).apply(binary)
        binary.save()
    finally:
        binary.close()

    transformed_result = run_command([mutated], timeout=30)
    crash_diagnostic = ""
    debugger = shutil.which("gdb")
    if transformed_result.returncode < 0 and debugger is not None:
        debug_result = run_command(
            [debugger, "-q", "-batch", "-ex", "run", "-ex", "bt", "--args", mutated],
            timeout=30,
            text=True,
        )
        crash_diagnostic = f" gdb_stdout={debug_result.stdout!r} gdb_stderr={debug_result.stderr!r}"
    expect(
        original_result.returncode == _EXPECTED_EXIT_CODE,
        f"native VEX sqrt fixture returned {original_result.returncode}: {original_result.stderr!r}",
    )
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS,
        f"VEX sqrt fixture was not sufficiently virtualized: {stats=}",
    )
    expect(
        transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX sqrt virtualization changed the result: returncode={transformed_result.returncode}, "
        f"stdout={transformed_result.stdout!r}, stderr={transformed_result.stderr!r}, {stats=}{crash_diagnostic}",
    )


def test_virtualized_vex_scalar_memory_sqrt_preserves_native_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX execution requires an x86-64 host")

    source = tmp_path / "vex_memory_sqrt.c"
    original = tmp_path / "original_memory"
    mutated = tmp_path / "mutated_memory"
    source.write_text(_MEMORY_SOURCE)
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx",
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
    expect(compile_result.returncode == 0, "failed to compile the native VEX memory sqrt fixture")
    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260837}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"VEX memory sqrt virtualization changed the result: {stats=}",
    )
