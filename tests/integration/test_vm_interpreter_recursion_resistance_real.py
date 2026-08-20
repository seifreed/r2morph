"""
The recursed layer resists devirtualization - a pinned property, by design.

Virtualizing a real interpreter's own dispatch loop (literal recursion) wraps it in the
region VM, whose dispatch is deliberately anti-devirtualization: threaded, no central
hub, register-indexed with XOR-encrypted offsets - not the absolute memory-indirect
``jmp [table+idx*8]`` shape the recovery oracle reconstructs. That is the region VM
working as designed, not a gap; recursion itself is proven behaviorally by the exit-code
round-trip in the sibling ``test_vm_interpreter_recursion_real``.

These pin the resistance the design buys, on the real recursively-virtualized binary
(no mocks): virtualizing the interpreter raises its structural devirtualization
resistance sharply, and the recovery oracle - which reconstructs absolute
memory-indirect handler tables - cannot reconstruct the region VM's handler set.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.analysis.symbolic.structural_resistance import StructuralResistance, StructuralResistanceProbe
from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from tests.integration import test_vm_interpreter_recursion_real as recursion
from tests.utils.assertions import expect

# The interpreter has four real handlers (loadi, addi, subi, halt); the oracle would
# need to reconstruct them all to devirtualize the recursed layer.
_REAL_HANDLER_COUNT = 4


def _measure(path: Path) -> StructuralResistance:
    binary = Binary(str(path))
    binary.open()
    try:
        binary.analyze("aa")
        return StructuralResistanceProbe(binary).measure()
    finally:
        binary.close()


@pytest.fixture(scope="module")
def recursively_virtualized(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Virtualize the interpreter's own dispatch loop once for the module."""
    dest = tmp_path_factory.mktemp("recursion_resistance") / "recursively_virtualized"
    shutil.copy(recursion.FIXTURE, dest)
    stats = recursion._run_pass(dest, virtualize_dispatch=True)
    expect(not (stats["functions_virtualized"] < 1))
    return dest


def test_recursed_layer_raises_structural_devirtualization_resistance(recursively_virtualized: Path) -> None:
    """The region VM lifts the interpreter's structural resistance well above the original."""
    original = _measure(recursion.FIXTURE)
    recursed = _measure(recursively_virtualized)
    expect(not (recursed.structural_score <= original.structural_score))
    expect(not (recursed.indirect_jumps <= original.indirect_jumps))


def test_devirt_oracle_cannot_reconstruct_the_recursed_layer(recursively_virtualized: Path) -> None:
    """The oracle cannot reconstruct the region VM's four real handlers - it has no table."""
    binary = Binary(str(recursively_virtualized))
    binary.open()
    try:
        binary.analyze("aa")
        expect(binary.r2 is not None)
        dispatcher = int(binary.r2.cmd("?v entry0").strip(), 16)
        arch = VMHandlerAnalyzer(binary).analyze_vm_architecture(dispatcher)
    finally:
        binary.close()
    expect(not (len(arch.handlers) >= _REAL_HANDLER_COUNT))
