"""Regression coverage for unwind-safe and unwind-unsafe functions."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

EXPECTED_EXIT_CODE = 42


def test_code_virtualization_limits_real_unwind_metadata_to_call_free_functions(tmp_path: Path) -> None:
    """Call-free code transforms while exception-propagating code stays native."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the unwind-safe virtualization contract is x86-64 specific")
    source = tmp_path / "unwind.cpp"
    executable = tmp_path / "unwind"
    source.write_text("""
#include <stdexcept>

__attribute__((noinline)) int safe_arithmetic(int value) {
    return value * 3 + 1;
}

int protected_function(int value) {
    try {
        if (value < 0) {
            throw std::runtime_error("negative");
        }
        return value + 1;
    } catch (const std::runtime_error&) {
        return 0;
    }
}

int main() { return safe_arithmetic(13) == 40 && protected_function(-1) == 0 ? 42 : 1; }
""")
    result = run_command(["g++", "-O0", "-fno-pie", "-no-pie", "-o", executable, source], timeout=30)
    expect(result.returncode == 0, "failed to compile the real unwinding fixture")

    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20}).apply(binary)

    runtime_result = run_command([executable], timeout=30)
    expect(
        stats["functions_virtualized"] > 0
        and stats["partial_virtualization_total"] > 0
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "unwind-safe partial virtualization changed the executable result",
    )
