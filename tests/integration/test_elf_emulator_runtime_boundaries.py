"""Regression coverage for ELF runtime-boundary emulation."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_tls_x86_64"
_GS_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_gs_tls_x86_64"
_SYSCALL_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_syscall_x86_64"
_EXPECTED_EXIT_CODE = 45
_EXPECTED_GS_EXIT_CODE = 46
_EXPECTED_SYSCALL_EXIT_CODE = 47

pytestmark = pytest.mark.integration


def test_elf_emulator_models_tls_initialization_and_exit() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_elf_emulator_preserves_tls_after_virtualization(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260827}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_elf_emulator_models_gs_initialization_and_exit() -> None:
    expect(emulate_exit_code(_GS_FIXTURE) == _EXPECTED_GS_EXIT_CODE)


def test_elf_emulator_preserves_gs_after_virtualization(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-gs"
    shutil.copyfile(_GS_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260827}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(emulate_exit_code(mutated) == _EXPECTED_GS_EXIT_CODE)


def test_elf_emulator_models_returning_syscall_and_exit() -> None:
    expect(emulate_exit_code(_SYSCALL_FIXTURE) == _EXPECTED_SYSCALL_EXIT_CODE)


def test_elf_emulator_preserves_returning_syscall_after_virtualization(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-syscall"
    shutil.copyfile(_SYSCALL_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260827}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_SYSCALL_EXIT_CODE)
