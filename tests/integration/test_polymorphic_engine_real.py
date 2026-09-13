"""Real-fixture regression coverage for composed mutation reporting."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_SEED = 20260913


def test_polymorphic_engine_reports_composed_mutations_and_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "elf_vm_arith_polymorphic"
    shutil.copyfile(_FIXTURE, mutated)
    baseline_exit_code = emulate_exit_code(_FIXTURE)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        result = PolymorphicEnginePass(config={"seed": _SEED, "max_iterations": 10}).apply(binary)
        binary.save()

    expect(
        result["mutations_applied"] > 0
        and result["mutations_applied"] == result["successful_mutations"]
        and result["failed_mutations"] == 0
        and emulate_exit_code(mutated) == baseline_exit_code
    )
