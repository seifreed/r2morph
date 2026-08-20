"""Regression: a virtualized callee must preserve its System V red zone."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_EXPECTED_STATS_FUNCTIONS_VIRTUALIZED_2 = 2


_FIXTURE = Path(__file__).parents[2] / "fixtures" / "dataset" / "elf_vm_redzone_x86_64"
_EXPECTED_EXIT_CODE = 42

pytest.importorskip("unicorn")


@pytest.fixture(scope="module")
def virtualized_redzone_fixture(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, int]]:
    destination = tmp_path_factory.mktemp("vm_redzone") / "virtualized"
    shutil.copy(_FIXTURE, destination)
    binary = Binary(str(destination), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "vm_nesting_depth": 1, "seed": 20260812}).apply(
            binary
        )
        binary.save()
    finally:
        binary.close()
    return destination, stats


def test_virtualized_redzone_fixture_virtualizes_caller_and_callee(
    virtualized_redzone_fixture: tuple[Path, dict[str, int]],
) -> None:
    _, stats = virtualized_redzone_fixture
    expect(stats["functions_virtualized"] == _EXPECTED_STATS_FUNCTIONS_VIRTUALIZED_2)


def test_virtualized_redzone_fixture_preserves_exit_code(
    virtualized_redzone_fixture: tuple[Path, dict[str, int]],
) -> None:
    destination, _ = virtualized_redzone_fixture
    expect(emulate_exit_code(destination) == emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)
