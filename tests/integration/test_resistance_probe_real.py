"""Regression: virtualization must raise a function's devirtualization resistance.

A generic symbolic adversary (angr) cracks the original fixture - it drives a
state to termination in a few steps, recovering the exit behaviour - but stalls
on the virtualized build, exhausting the step budget without terminating. This is
the metric that scores every VM-hardening advance: a change that did not make the
VM harder to devirtualize would not move this number.

No mocks: a real Binary, the real radare2-native virtualization, and a real angr
symbolic exploration. Skips cleanly when the angr backend is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.analysis.symbolic.resistance_probe import ResistanceMeasurement, SymbolicResistanceProbe
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
FIXTURE = _DATASET / "elf_vm_shift_x86_64"

# Tight budget: the original terminates in a handful of steps, so a small budget
# still cracks it, while the virtualized build cannot terminate within it. Keeps
# the exploration sub-second.
_STEP_BUDGET = 200


def _virtualize(src: Path, dst: Path) -> None:
    shutil.copy(src, dst)
    binary = Binary(str(dst), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))


def _measure(path: Path) -> ResistanceMeasurement:
    binary = Binary(str(path))
    binary.open()
    try:
        return SymbolicResistanceProbe(binary).measure(step_budget=_STEP_BUDGET)
    finally:
        binary.close()


def test_virtualization_raises_symbolic_resistance(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    _virtualize(FIXTURE, mutated)

    original = _measure(FIXTURE)
    if not original.angr_available:
        pytest.skip("angr backend unavailable")
    virtualized = _measure(mutated)

    # The adversary cracks the original quickly but never terminates on the VM,
    # so virtualization strictly raises the resistance score.
    expect(not (original.reached_terminal is not True))
    expect(not (virtualized.reached_terminal is not False))
    expect(not (virtualized.resistance_score <= original.resistance_score))


def test_budget_limited_virtualized_run_is_flagged_as_lower_bound(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    _virtualize(FIXTURE, mutated)

    virtualized = _measure(mutated)
    if not virtualized.angr_available:
        pytest.skip("angr backend unavailable")

    # The 1.0 score came from the small budget, not from a proof of resistance:
    # the run must announce that it stopped short of natural completion.
    expect(not (virtualized.reached_terminal is not False))
    expect(virtualized.resistance_score == 1.0)
    expect(not (virtualized.budget_exhausted is not True))


def test_cracked_original_run_reports_no_budget_exhaustion(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    original = _measure(FIXTURE)
    if not original.angr_available:
        pytest.skip("angr backend unavailable")

    # A genuine crack terminates within budget without truncation, so the honesty
    # flag stays False - the low score is proven, not a lower bound.
    expect(not (original.reached_terminal is not True))
    expect(not (original.budget_exhausted is not False))
