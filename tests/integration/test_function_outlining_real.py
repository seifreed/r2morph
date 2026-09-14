"""Native regression coverage for outlining radare2 ``addr`` streams."""

from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.function_outlining import FunctionOutliningPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex_word_shuffle_x86_64"
_EXPECTED_EXIT_CODE = 42


@pytest.mark.skipif(
    sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"},
    reason="native ELF x86-64 outlining requires a Linux x86-64 host",
)
def test_function_outlining_preserves_vex_word_shuffle_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_vex_word_shuffle"
    shutil.copy(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        stats = FunctionOutliningPass({"probability": 1.0, "max_functions": 1, "seed": 20260902}).apply(binary)
        binary.save()

    expect(stats["functions_outlined"] == 1, "VEX word shuffle fixture was not outlined")
    result = run_command([mutated], timeout=30)
    expect(
        result.returncode == _EXPECTED_EXIT_CODE,
        f"outlined VEX word shuffle fixture returned {result.returncode}, expected {_EXPECTED_EXIT_CODE}",
    )
