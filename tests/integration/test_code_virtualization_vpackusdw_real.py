"""Native regression coverage for VEX.256 unsigned word packing."""

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

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex256_packusdw_x86_64"
_MEMORY_FIXTURE = (
    Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex256_packusdw_mem_x86_64"
)
_EXPECTED_EXIT_CODE = 42


def test_vpackusdw_fixture_original_returns_expected_code() -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    result = run_command([_FIXTURE], timeout=30)

    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )


def test_vpackusdw_fixture_virtualization_preserves_saturation_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    mutated = tmp_path / "mutated_vpackusdw"
    shutil.copy(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260913}).apply(binary)
        binary.save()

    result = run_command([mutated], timeout=30)

    expect(stats["functions_virtualized"] >= 1, f"vpackusdw fixture was not virtualized: {stats=}")
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualized vpackusdw fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}; "
        f"stdout={result.stdout!r}, stderr={result.stderr!r}",
    )


def test_vpackusdw_memory_fixture_original_returns_expected_code() -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    result = run_command([_MEMORY_FIXTURE], timeout=30)

    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"memory fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )


def test_vpackusdw_memory_fixture_virtualization_preserves_saturation_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native AVX2 execution requires an x86-64 host")

    mutated = tmp_path / "mutated_vpackusdw_memory"
    shutil.copy(_MEMORY_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260914}).apply(binary)
        binary.save()

    result = run_command([mutated], timeout=30)

    expect(stats["functions_virtualized"] >= 1, f"memory vpackusdw fixture was not virtualized: {stats=}")
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"virtualized memory vpackusdw fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}; "
        f"stdout={result.stdout!r}, stderr={result.stderr!r}",
    )
