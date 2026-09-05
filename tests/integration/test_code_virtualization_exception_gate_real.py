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


def test_code_virtualization_preserves_real_unwind_metadata_for_synchronous_exceptions(tmp_path: Path) -> None:
    """A parsed landing-pad frame remains valid when the VM run has no call."""
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
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1000}).apply(binary)

    runtime_result = run_command([executable], timeout=30)
    unwind_failure_addresses = {
        record["function_address"]
        for record in stats["unsupported_functions"] + stats["partial_virtualization"]
        if record["capability"] == "exceptions_and_unwinding"
    }
    expect(
        stats["functions_virtualized"] > 0
        and stats["partial_virtualization_total"] > 0
        and protected_address not in unwind_failure_addresses
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "parsed landing-pad unwind metadata was not preserved during virtualization: "
        f"{protected_address=:#x}, {runtime_result.returncode=}, {unwind_failure_addresses=}, {stats=}",
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


def test_code_virtualization_preserves_exception_from_call_inside_virtualized_function(tmp_path: Path) -> None:
    """A call that can unwind through a VM body is rejected without mutation."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the unwind-safe virtualization contract is x86-64 specific")
    thrower_source = tmp_path / "unwind_thrower.cpp"
    source = tmp_path / "unwind_call.cpp"
    executable = tmp_path / "unwind_call"
    thrower_source.write_text("""
#include <stdexcept>

void thrower() {
    throw std::runtime_error("call escaped");
}
""")
    source.write_text("""
#include <stdexcept>

extern void thrower();

__attribute__((noinline)) int boundary(int value) {
    thrower();
    return value;
}

__attribute__((noinline)) int caller() {
    try {
        boundary(35);
        return 1;
    } catch (const std::runtime_error&) {
        return 42;
    }
}

int main() { return caller(); }
""")
    result = run_command(["g++", "-O2", "-fno-pie", "-no-pie", "-o", executable, thrower_source, source], timeout=30)
    expect(result.returncode == 0, "failed to compile the call/unwinding fixture")

    with Binary(executable, writable=True) as binary:
        binary.analyze()
        boundary_address = next(
            int(function["addr"]) for function in binary.get_functions() if "boundary" in function.get("name", "")
        )
        original_boundary_bytes = binary.read_bytes(boundary_address, 8)
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1000}).apply(binary)
        boundary_was_transformed = binary.read_bytes(boundary_address, 8) != original_boundary_bytes

    runtime_result = run_command([executable], timeout=30)
    unwind_failure_addresses = {
        record["function_address"]
        for record in stats["unsupported_functions"] + stats["partial_virtualization"]
        if record["capability"] == "exceptions_and_unwinding"
    }
    expect(
        not boundary_was_transformed
        and boundary_address in unwind_failure_addresses
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "a call with an exception edge crossing the VM was not rejected safely: "
        f"{boundary_address=:#x}, {boundary_was_transformed=}, {runtime_result.returncode=}, "
        f"{unwind_failure_addresses=}, {stats=}",
    )
