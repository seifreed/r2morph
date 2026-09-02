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
        binary.analyze()
        protected_address = next(
            int(function["addr"])
            for function in binary.get_functions()
            if "protected_function" in function.get("name", "")
        )
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20}).apply(binary)

    runtime_result = run_command([executable], timeout=30)
    unsupported_addresses = {record["function_address"] for record in stats["unsupported_functions"]}
    partial_addresses = {record["function_address"] for record in stats["partial_virtualization"]}
    expect(
        stats["functions_virtualized"] > 0
        and stats["partial_virtualization_total"] > 0
        and protected_address in unsupported_addresses
        and protected_address not in partial_addresses
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "landing-pad unwind metadata was not rejected before relocation",
    )


def test_code_virtualization_does_not_globally_degrade_unwind_free_function(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the unwind-safe virtualization contract is x86-64 specific")
    source = tmp_path / "unwind_scope.cpp"
    executable = tmp_path / "unwind_scope"
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
    result = run_command(["g++", "-O2", "-fno-pie", "-no-pie", "-o", executable, source], timeout=30)
    expect(result.returncode == 0, "failed to compile the scoped unwinding fixture")

    with Binary(executable, writable=True) as binary:
        binary.analyze()
        safe_address = next(
            int(function["addr"])
            for function in binary.get_functions()
            if "safe_arithmetic" in function.get("name", "")
        )
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20}).apply(binary)

    degraded_addresses = {record["function_address"] for record in stats["partial_virtualization"]}
    expect(safe_address not in degraded_addresses, "unwind metadata from another function degraded safe_arithmetic")
