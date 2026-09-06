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
FIXTURE_SEED = 20260827


def test_code_virtualization_rejects_lsda_function_without_mutation(tmp_path: Path) -> None:
    """An LSDA-bearing function is rejected until its call sites can be mapped."""
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
        original_protected_bytes = binary.read_bytes(protected_address, 8)
        stats = CodeVirtualizationPass(
            config={
                "probability": 1.0,
                "max_functions": 1000,
                "reject_partial_virtualization": False,
                "seed": FIXTURE_SEED,
            }
        ).apply(binary)
        protected_was_transformed = binary.read_bytes(protected_address, 8) != original_protected_bytes

    runtime_result = run_command([executable], timeout=30)
    unwind_failure_addresses = {
        record["function_address"]
        for record in stats["unsupported_functions"] + stats["partial_virtualization"]
        if record["capability"] == "exceptions_and_unwinding"
    }
    expect(
        stats["functions_virtualized"] > 0
        and not protected_was_transformed
        and protected_address in unwind_failure_addresses
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "an LSDA-bearing function was not rejected safely: "
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
        stats = CodeVirtualizationPass(
            config={
                "probability": 1.0,
                "max_functions": 20,
                "reject_partial_virtualization": False,
                "seed": FIXTURE_SEED,
            }
        ).apply(binary)

    degraded_addresses = {record["function_address"] for record in stats["partial_virtualization"]}
    expect(safe_address not in degraded_addresses, "unwind metadata from another function degraded safe_arithmetic")


def test_code_virtualization_preserves_native_call_with_ordinary_eh_frame(tmp_path: Path) -> None:
    """An ordinary FDE without LSDA remains safe across a VM call bridge."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the unwind-safe virtualization contract is x86-64 specific")
    source = tmp_path / "ordinary_call.cpp"
    executable = tmp_path / "ordinary_call"
    source.write_text("""
__attribute__((noinline)) int helper(int value) { return value * 2; }
__attribute__((noinline)) int caller(int value) { return helper(value) + 1; }
int main() { return caller(20) == 41 ? 42 : 1; }
""")
    result = run_command(
        ["g++", "-O0", "-fno-pie", "-no-pie", "-funwind-tables", "-o", executable, source],
        timeout=30,
    )
    expect(result.returncode == 0, "failed to compile the ordinary unwind fixture")

    with Binary(executable, writable=True) as binary:
        binary.analyze()
        caller_address = next(
            int(function["addr"]) for function in binary.get_functions() if "caller" in function.get("name", "")
        )
        original_bytes = binary.read_bytes(caller_address, 8)
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1000, "seed": FIXTURE_SEED}).apply(
            binary
        )
        caller_transformed = binary.read_bytes(caller_address, 8) != original_bytes

    runtime_result = run_command([executable], timeout=30)
    unwind_failures = {
        record["function_address"]
        for record in stats["unsupported_functions"] + stats["partial_virtualization"]
        if record["capability"] == "exceptions_and_unwinding"
    }
    expect(
        caller_transformed
        and caller_address not in unwind_failures
        and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "an ordinary native call was rejected by the ELF unwind gate: "
        f"{caller_address=:#x}, {caller_transformed=}, {runtime_result.returncode=}, {stats=}",
    )


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
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1000, "seed": FIXTURE_SEED}).apply(
            binary
        )
        boundary_was_transformed = binary.read_bytes(boundary_address, 8) != original_boundary_bytes

    runtime_result = run_command([executable], timeout=30)
    unwind_failure_addresses = {
        record["function_address"]
        for record in stats["unsupported_functions"] + stats["partial_virtualization"]
        if record["capability"] == "exceptions_and_unwinding"
    }
    expect(
        not boundary_was_transformed and unwind_failure_addresses and runtime_result.returncode == EXPECTED_EXIT_CODE,
        "a call with an exception edge crossing the VM was not rejected safely: "
        f"{boundary_address=:#x}, {boundary_was_transformed=}, {runtime_result.returncode=}, "
        f"{unwind_failure_addresses=}, {stats=}",
    )
