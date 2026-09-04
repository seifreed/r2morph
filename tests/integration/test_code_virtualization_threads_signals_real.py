"""Regression coverage for thread-local state and signal delivery."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 13
_EXPECTED_ASYNC_SIGNAL_EXIT_CODE = 17

_SOURCE = r"""
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

static volatile sig_atomic_t signal_seen;
static _Thread_local volatile unsigned long thread_value;

static void on_signal(int signal_number) {
    (void)signal_number;
    signal_seen = 1;
    thread_value += 3UL;
}

__attribute__((noinline)) static void *thread_entry(void *argument) {
    thread_value = (unsigned long)(size_t)argument;
    return NULL;
}

int main(void) {
    pthread_t thread;
    thread_value = 9UL;
    signal(SIGUSR1, on_signal);
    if (pthread_create(&thread, NULL, thread_entry, (void *)5UL) != 0) {
        return 1;
    }
    if (pthread_join(thread, NULL) != 0) {
        return 2;
    }
    raise(SIGUSR1);
    return (int)(thread_value + (unsigned long)signal_seen) & 127;
}
"""


def test_virtualized_threads_tls_and_signal_preserve_exit_code(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("the regression requires Linux amd64 ELF execution")

    source = tmp_path / "threads_signals.c"
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
    expect(compile_result.returncode == 0, "failed to compile the Linux thread/signal fixture")

    original_result = run_command([original], timeout=30)
    binary = Binary(original, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(
            config={"probability": 1.0, "seed": 20260829, "virtualize_dispatch": True}
        ).apply(binary)
        binary.save()
    finally:
        binary.close()
    original.rename(mutated)
    transformed_result = run_command([mutated], timeout=30)

    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualization changed thread/TLS/signal behavior: {stats=}",
    )


def test_virtualized_async_signal_inside_vm_preserves_exit_code(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("the regression requires Linux amd64 ELF execution")

    source = tmp_path / "async_signal.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(r"""
#include <signal.h>
#include <stddef.h>
#include <sys/time.h>

static volatile sig_atomic_t signal_seen;

static void on_alarm(int signal_number) {
    (void)signal_number;
    signal_seen = 1;
}

__attribute__((noinline)) static int wait_for_alarm(void) {
    volatile unsigned long iterations = 0;
    while (!signal_seen) {
        ++iterations;
    }
    return iterations != 0 ? 17 : 1;
}

int main(void) {
    struct itimerval timer = { {0, 1000}, {0, 1000} };
    signal(SIGALRM, on_alarm);
    setitimer(ITIMER_REAL, &timer, NULL);
    return wait_for_alarm();
}
""")
    compile_result = run_command(
        [
            "gcc",
            "-O2",
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
    expect(compile_result.returncode == 0, "failed to compile the asynchronous signal fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260830}).apply(binary)
        binary.save()
    finally:
        binary.close()
    transformed_result = run_command([mutated], timeout=30)

    expect(
        stats["functions_virtualized"] >= 1
        and original_result.returncode == transformed_result.returncode == _EXPECTED_ASYNC_SIGNAL_EXIT_CODE,
        f"virtualization changed async signal behavior inside the VM: {stats=}, "
        f"original={original_result.returncode}, transformed={transformed_result.returncode}",
    )
