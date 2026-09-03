"""Native regression coverage for VEX word shuffle immediates."""

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

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex_word_shuffle_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_vex_word_shuffle_fixture_original_returns_expected_exit_code(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX execution requires an x86-64 host")

    original = tmp_path / "original_vex_word_shuffle"
    shutil.copy(_FIXTURE, original)
    result = run_command([original], timeout=30)
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"original VEX word shuffle fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )


def test_vex_word_shuffle_fixture_virtualization_preserves_xmm_and_ymm(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_vex_word_shuffle"
    shutil.copy(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": 20260915}).apply(binary)
        binary.save()
    expect(stats["functions_virtualized"] == 1, "VEX word shuffle fixture function was not virtualized")
    if platform.machine().lower() in {"x86_64", "amd64"}:
        result = run_command([mutated], timeout=30)
        expect(
            result.returncode == _EXPECTED_EXIT_CODE,
            f"virtualized VEX word shuffle fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}; "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
