"""Native ELF regression coverage for atomic memory exchange."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_thread_xchg_x86_64"
_CMPXCHG_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_thread_cmpxchg_x86_64"
_ATOMIC_IMMEDIATE_FIXTURE = (
    Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_thread_mematomicimm_x86_64"
)
_EXPECTED_EXIT_CODE = 42
_MINIMUM_ATOMIC_IMMEDIATE_INSTRUCTIONS = 5

pytestmark = pytest.mark.integration


def _virtualize_fixture(tmp_path: Path, fixture: Path = _FIXTURE) -> tuple[Path, Path, dict[str, object]]:
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copyfile(fixture, original)
    shutil.copyfile(fixture, mutated)
    original.chmod(original.stat().st_mode | stat.S_IXUSR)
    mutated.chmod(mutated.stat().st_mode | stat.S_IXUSR)

    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260831}).apply(binary)
        binary.save()
    return original, mutated, stats


def test_atomic_xchg_fixture_virtualization_preserves_emulated_exchange(tmp_path: Path) -> None:
    _original, mutated, stats = _virtualize_fixture(tmp_path)

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


@pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native ELF x86-64 execution requires Linux amd64",
)
def test_atomic_xchg_fixture_virtualization_preserves_native_exchange(tmp_path: Path) -> None:
    original, mutated, stats = _virtualize_fixture(tmp_path)

    original_result = run_command([str(original)], capture_output=True, timeout=5)
    mutated_result = run_command([str(mutated)], capture_output=True, timeout=5)
    expect(stats["functions_virtualized"] >= 1)
    expect((original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE))


def test_atomic_cmpxchg_fixture_virtualization_preserves_compare_exchange(tmp_path: Path) -> None:
    _original, mutated, stats = _virtualize_fixture(tmp_path, _CMPXCHG_FIXTURE)

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


@pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native ELF x86-64 execution requires Linux amd64",
)
def test_atomic_cmpxchg_fixture_virtualization_preserves_native_compare_exchange(tmp_path: Path) -> None:
    original, mutated, stats = _virtualize_fixture(tmp_path, _CMPXCHG_FIXTURE)

    original_result = run_command([str(original)], capture_output=True, timeout=5)
    mutated_result = run_command([str(mutated)], capture_output=True, timeout=5)
    expect(stats["functions_virtualized"] >= 1)
    expect((original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE))


def test_atomic_immediate_fixture_virtualization_preserves_emulated_updates(tmp_path: Path) -> None:
    _original, mutated, stats = _virtualize_fixture(tmp_path, _ATOMIC_IMMEDIATE_FIXTURE)

    expect(stats["total_instructions"] >= _MINIMUM_ATOMIC_IMMEDIATE_INSTRUCTIONS)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_atomic_immediate_fixture_virtualizes_memory_comparisons(tmp_path: Path) -> None:
    _original, _mutated, stats = _virtualize_fixture(tmp_path, _ATOMIC_IMMEDIATE_FIXTURE)

    expect(not any(record["capability"] == "memory_operands" for record in stats["partial_virtualization"]))


@pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native ELF x86-64 execution requires Linux amd64",
)
def test_atomic_immediate_fixture_virtualization_preserves_native_updates(tmp_path: Path) -> None:
    original, mutated, stats = _virtualize_fixture(tmp_path, _ATOMIC_IMMEDIATE_FIXTURE)

    original_result = run_command([str(original)], capture_output=True, timeout=5)
    mutated_result = run_command([str(mutated)], capture_output=True, timeout=5)
    expect(stats["total_instructions"] >= _MINIMUM_ATOMIC_IMMEDIATE_INSTRUCTIONS)
    expect((original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE))
