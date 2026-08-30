"""Native Linux regression coverage for locked memory read-modify-write."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 23

_XADD_SOURCE = r"""
#include <stdint.h>

static volatile unsigned counter;

__attribute__((noinline)) static unsigned increment_and_return_old(unsigned delta) {
    __asm__ volatile("lock xaddl %1, %0" : "+m"(counter), "+r"(delta) : : "memory", "cc");
    return delta;
}

int main(void) {
    return increment_and_return_old(7) == 0 && counter == 7 ? 23 : 3;
}
"""

_SOURCE = r"""
#include <pthread.h>
#include <stdint.h>

static volatile unsigned counter;

__attribute__((noinline)) static void *worker(void *argument) {
    unsigned iterations = (unsigned)(uintptr_t)argument;
    for (unsigned index = 0; index < iterations; ++index) {
        unsigned delta = 1;
        __asm__ volatile("lock addl %1, %0" : "+m"(counter) : "r"(delta) : "memory", "cc");
    }
    return 0;
}

int main(void) {
    pthread_t threads[4];
    for (unsigned index = 0; index < 4; ++index) {
        if (pthread_create(&threads[index], 0, worker, (void *)(uintptr_t)1000) != 0) {
            return 1;
        }
    }
    for (unsigned index = 0; index < 4; ++index) {
        if (pthread_join(threads[index], 0) != 0) {
            return 2;
        }
    }
    return counter == 4000 ? 23 : 3;
}
"""


def test_virtualized_locked_memory_rmw_preserves_threaded_counter(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("the regression requires Linux amd64 ELF execution")

    source = tmp_path / "atomic_rmw.c"
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
            "-pthread",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the locked-RMW fixture")

    original_result = run_command([original], timeout=30)
    binary = Binary(original, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260830}).apply(binary)
        binary.save(mutated)
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)

    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualization changed locked-RMW behavior: {stats=}",
    )


def test_virtualized_locked_xadd_preserves_previous_memory_value(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("the regression requires Linux amd64 ELF execution")

    source = tmp_path / "atomic_xadd.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(_XADD_SOURCE)
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
    expect(compile_result.returncode == 0, "failed to compile the locked-xadd fixture")

    original_result = run_command([original], timeout=30)
    binary = Binary(original, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260832}).apply(binary)
        binary.save(mutated)
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)

    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualization changed locked-xadd behavior: {stats=}",
    )
