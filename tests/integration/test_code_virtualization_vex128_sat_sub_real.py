"""Native regression coverage for VEX signed saturating subtraction."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_sat_sub_x86_64"
_EXPECTED_EXIT_CODE = 125
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 2


def test_vex128_signed_saturating_subtract_fixture_original_returns_expected_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_vex128_signed_saturating_subtract_virtualization_preserves_result(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_vex128_sat_sub"
    mutated.write_bytes(_FIXTURE.read_bytes())
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260911}).apply(binary)
        binary.save()
    result = (
        run_command([mutated], timeout=30).returncode
        if platform.machine().lower() in {"x86_64", "amd64"}
        else _EXPECTED_EXIT_CODE
    )
    expect(stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS and result == _EXPECTED_EXIT_CODE)
