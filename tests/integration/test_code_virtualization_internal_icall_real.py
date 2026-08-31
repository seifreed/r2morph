"""Regression coverage for statically proven local register-indirect calls."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.adapters.process import run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect

_EXPECTED_EXIT_CODE = 42
_EXPECTED_MEMORY_INDIRECT_EXIT_CODE = 43
_SOURCE = r"""
__attribute__((noinline)) int indirect_local(int value) {
    int result;
    asm volatile(
        "lea 1f(%%rip), %%rax\n"
        "call *%%rax\n"
        "mov %%eax, %0\n"
        "jmp 2f\n"
        "1:\n"
        "add $5, %%edi\n"
        "mov %%edi, %%eax\n"
        "ret\n"
        "2:\n"
        : "=a"(result), "+D"(value)
        :
        : "cc", "memory");
    return result;
}

int main(void) {
    return indirect_local(37) == 42 ? 42 : 1;
}
"""

_MEMORY_INDIRECT_SOURCE = r"""
#include <stdlib.h>

typedef int (*transform_fn)(int);

static transform_fn volatile transform = abs;

__attribute__((noinline)) static int external_indirect(int value) {
    return transform(value);
}

int main(void) {
    return external_indirect(-43) == 43 ? 43 : 1;
}
"""


def _compile_fixture(tmp_path: Path, compiler: str) -> Path:
    source = tmp_path / "internal_icall.c"
    binary = tmp_path / "internal_icall"
    source.write_text(_SOURCE)
    run_process(
        [
            compiler,
            "-O2",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
    )
    return binary


@pytest.mark.integration
def test_virtualized_local_indirect_call_preserves_exit_code(tmp_path: Path) -> None:
    """A local ``call reg`` is re-entered in the VM and returns through ``vret``."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("fixture requires x86-64 execution")
    if shutil.which("gcc") is None:
        pytest.skip("fixture requires gcc")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("fixture requires gcc")
    fixture = _compile_fixture(tmp_path, compiler)
    mutated = tmp_path / "mutated_internal_icall"
    shutil.copy(fixture, mutated)
    original_result = run_process([fixture])
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 2, "seed": 20260830}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(stats["functions_virtualized"] >= 1)
    mutated_result = run_process([mutated])
    expect(original_result.returncode == mutated_result.returncode == _EXPECTED_EXIT_CODE)


def test_virtualized_memory_indirect_call_preserves_external_result(tmp_path: Path) -> None:
    """A volatile function pointer uses the memory-indirect native-call bridge."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("fixture requires x86-64 execution")
    if shutil.which("gcc") is None:
        pytest.skip("fixture requires gcc")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("fixture requires gcc")
    source = tmp_path / "memory_indirect.c"
    fixture = tmp_path / "memory_indirect"
    mutated = tmp_path / "mutated_memory_indirect"
    source.write_text(_MEMORY_INDIRECT_SOURCE)
    run_process(
        [
            compiler,
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            str(source),
            "-o",
            str(fixture),
        ],
        check=True,
    )
    shutil.copy(fixture, mutated)
    original_result = run_process([fixture])
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260901}).apply(binary)
        binary.save()
    finally:
        binary.close()
    mutated_result = run_process([mutated])
    expect(stats["functions_virtualized"] >= 1)
    expect(original_result.returncode == mutated_result.returncode == _EXPECTED_MEMORY_INDIRECT_EXIT_CODE)
