"""Regression: the injected VM interpreter makes a binary structurally complex.

The static structural signal must rank a virtualized build strictly above the
original, which carries no interpreter. Unlike the symbolic metric this signal
does not saturate, so it can score incremental VM hardening. Real Binary, real
radare2-native virtualization, real disassembly - no mocks. Skips when radare2 is
unavailable.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.analysis.symbolic.structural_resistance import StructuralResistance, StructuralResistanceProbe
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

_DATASET = Path(__file__).resolve().parents[1].parent / "dataset"
FIXTURE = _DATASET / "elf_vm_shift_x86_64"


def _measure(path: Path, baseline: int | None = None) -> StructuralResistance:
    binary = Binary(str(path))
    binary.open()
    try:
        return StructuralResistanceProbe(binary).measure(baseline_instructions=baseline)
    finally:
        binary.close()


def test_virtualization_raises_structural_resistance(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    assert stats["functions_virtualized"] >= 1

    original = _measure(FIXTURE)
    if original.total_instructions == 0:
        pytest.skip("radare2 unavailable or produced no disassembly")
    virtualized = _measure(mutated, baseline=original.total_instructions)

    # The interpreter dominates the virtualized build: strictly higher score, a real
    # expansion over the native run, and far more dispatch branching. The dispatch
    # shape varies per build - the threaded shape adds indirect computed gotos, the
    # switch shape adds a large direct compare/branch ladder - so the added branching
    # is counted across both indirect jumps and distinct branch targets, which holds
    # whichever shape this build drew.
    assert virtualized.structural_score > original.structural_score
    assert virtualized.expansion_ratio > 1.0
    assert (
        virtualized.indirect_jumps + virtualized.distinct_branch_targets
        > original.indirect_jumps + original.distinct_branch_targets
    )
