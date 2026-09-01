"""Regression coverage for statically proven local register-indirect calls."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.adapters.process import run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_EXPECTED_EXIT_CODE = 42
_EXPECTED_MEMORY_INDIRECT_EXIT_CODE = 43
_EXPECTED_LOCAL_MEMORY_INDIRECT_EXIT_CODE = 43
_CALL_FALLBACK_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_run_callfallback_x86_64"
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

_LOCAL_MEMORY_INDIRECT_SOURCE = r"""
__attribute__((noinline)) int local_memory_indirect(int value) {
    int result;
    asm volatile(
        "lea 1f(%%rip), %%rax\n"
        "mov %%rax, -8(%%rsp)\n"
        "call *-8(%%rsp)\n"
        "mov %%eax, %0\n"
        "jmp 2f\n"
        "1:\n"
        "add $6, %%edi\n"
        "mov %%edi, %%eax\n"
        "ret\n"
        "2:\n"
        : "=a"(result), "+D"(value)
        :
        : "cc", "memory");
    return result;
}

int main(void) {
    return local_memory_indirect(37) == 43 ? 43 : 1;
}
"""

_MEMORY_INDIRECT_STACK_ARGUMENT_SOURCE = r"""
typedef long (*sum_fn)(long, long, long, long, long, long, long, long);

__attribute__((noinline)) static long sum_eight(
    long first, long second, long third, long fourth,
    long fifth, long sixth, long seventh, long eighth
) {
    return first + second + third + fourth + fifth + sixth + seventh + eighth;
}

static sum_fn volatile target = sum_eight;

__attribute__((noinline)) static long invoke_indirect_sum(void) {
    return target(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L);
}

int main(void) {
    return invoke_indirect_sum() == 36L ? 44 : 1;
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


def test_virtualized_local_memory_indirect_call_preserves_exit_code(tmp_path: Path) -> None:
    """A stack-stored local target keeps its native result after virtualization."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("fixture requires x86-64 execution")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("fixture requires gcc")
    source = tmp_path / "local_memory_indirect.c"
    fixture = tmp_path / "local_memory_indirect"
    mutated = tmp_path / "mutated_local_memory_indirect"
    source.write_text(_LOCAL_MEMORY_INDIRECT_SOURCE)
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
            str(fixture),
        ],
        check=True,
    )
    shutil.copy(fixture, mutated)
    original_result = run_process([fixture])
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 4, "seed": 20260904}).apply(binary)
        binary.save()
    finally:
        binary.close()
    mutated_result = run_process([mutated])
    expect(stats["functions_virtualized"] >= 1)
    expect(original_result.returncode == mutated_result.returncode == _EXPECTED_LOCAL_MEMORY_INDIRECT_EXIT_CODE)


def test_virtualized_memory_indirect_call_with_stack_arguments_preserves_exit_code(tmp_path: Path) -> None:
    """A memory-indirect call keeps arguments beyond the six register slots."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("fixture requires x86-64 execution")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("fixture requires gcc")
    source = tmp_path / "memory_indirect_stack_arguments.c"
    fixture = tmp_path / "memory_indirect_stack_arguments"
    mutated = tmp_path / "mutated_memory_indirect_stack_arguments"
    source.write_text(_MEMORY_INDIRECT_STACK_ARGUMENT_SOURCE)
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
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 8, "seed": 20260906}).apply(binary)
        binary.save()
    finally:
        binary.close()
    mutated_result = run_process([mutated])
    expect(stats["functions_virtualized"] >= 1)
    expect(original_result.returncode == mutated_result.returncode == 44)


def test_virtualized_direct_call_to_separate_function_preserves_exit_code(tmp_path: Path) -> None:
    """A caller whose callee ret is included by linear disassembly stays whole-function virtualized."""
    mutated = tmp_path / "mutated_direct_call"
    shutil.copyfile(_CALL_FALLBACK_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(
            config={"probability": 1.0, "max_functions": 2, "reject_partial_virtualization": True, "seed": 20260903}
        ).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1 and stats["partial_virtualization_total"] == 0)
    expect(emulate_exit_code(mutated) == emulate_exit_code(_CALL_FALLBACK_FIXTURE))
