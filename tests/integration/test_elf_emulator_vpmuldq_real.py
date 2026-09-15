"""Unicorn oracle coverage for VEX.128 integer multiplication."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

pytestmark = pytest.mark.integration

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vpmuldq_x86_64"
_UNSIGNED_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vpmuludq_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_vpmuldq_fixture_emulator_preserves_result() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE, "VPMULDQ emulator result diverged")


def test_vpmuludq_fixture_emulator_preserves_result() -> None:
    expect(emulate_exit_code(_UNSIGNED_FIXTURE) == _EXPECTED_EXIT_CODE, "VPMULUDQ emulator result diverged")
