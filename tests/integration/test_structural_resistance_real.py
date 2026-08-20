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
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
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
    expect(not (stats["functions_virtualized"] < 1))

    original = _measure(FIXTURE)
    if original.total_instructions == 0:
        pytest.skip("radare2 unavailable or produced no disassembly")
    virtualized = _measure(mutated, baseline=original.total_instructions)

    # The interpreter dominates the virtualized build: strictly higher score, a real
    # expansion over the native run, and far more dispatch branching. The threaded
    # dispatch adds an indirect computed goto per handler tail plus the handler
    # labels themselves, so the added branching is counted across both indirect
    # jumps and distinct branch targets.
    expect(not (virtualized.structural_score <= original.structural_score))
    expect(not (virtualized.expansion_ratio <= 1.0))
    expect(
        not (
            virtualized.indirect_jumps + virtualized.distinct_branch_targets
            <= original.indirect_jumps + original.distinct_branch_targets
        )
    )


def test_structural_probe_counts_inline_executable_payload(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-fragmented"
    shutil.copy(FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))

    binary = Binary(str(mutated))
    binary.open()
    try:
        executable = [segment for segment in binary.r2.cmdj("iSSj") or [] if "x" in segment.get("perm", "")]
        counts = []
        for segment in executable:
            size = min(int(segment.get("vsize", 0)), 1 << 20)
            ops = binary.r2.cmdj(f"pDj {size} @ {int(segment['vaddr'])}") or []
            counts.append(sum(op.get("type") not in (None, "invalid") and "disasm" in op for op in ops))
        measured = StructuralResistanceProbe(binary).measure()
    finally:
        binary.close()

    expect(len(counts) == 1)
    expect(measured.total_instructions == sum(counts))
