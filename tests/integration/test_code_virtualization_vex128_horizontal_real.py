"""Native regression coverage for horizontal VEX packed operations."""

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

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_horizontal_x86_64"
_EXPECTED_EXIT_CODE = 42
_MINIMUM_VIRTUALIZED_INSTRUCTIONS = 6


def test_vex128_horizontal_fixture_virtualization_preserves_result(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_vex128_horizontal"
    shutil.copy(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260912}).apply(binary)
        binary.save()
    expect(
        stats["total_instructions"] >= _MINIMUM_VIRTUALIZED_INSTRUCTIONS,
        f"virtualized only {stats['total_instructions']} instructions, "
        f"expected at least {_MINIMUM_VIRTUALIZED_INSTRUCTIONS}",
    )
    if platform.machine().lower() in {"x86_64", "amd64"}:
        result = run_command([mutated], timeout=30)
        expect(
            result.returncode == _EXPECTED_EXIT_CODE,
            f"virtualized horizontal fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}; "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
