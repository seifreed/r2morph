"""
Virtualizing an interpreter whose flags cross the dispatch (pushfq/popfq).

``dataset/elf_vm_interp_stack_x86_64`` is a bytecode interpreter with the classic
register-indirect dispatch plus a "check" opcode that preserves a condition flag
across a flag-live scratch computation by bracketing it with ``pushfq``/``popfq`` -
the flag-preservation idiom, the shape where flag state crosses the computed jump.
Before flag-transfer support the pushfq made the whole function unclassifiable, so
the opt-in dispatch path left it native; now the region lowers pushfq/popfq to
fsave/frestore (virtual RFLAGS saved to and restored from the vstack) and the whole
interpreter virtualizes.

The fixture is load-bearing: the accumulator only stays 45 if the preserved
condition survives the bracket, so a broken save/restore changes the exit code.

These drive the real pass on a real binary - no r2 stubs, no mocks. With
``virtualize_dispatch`` enabled the function extracts into an ijmp region carrying
fsave/frestore items and the mutated binary still emulates to 45; with the flag off
(the default) the dispatch function is left untouched.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration import test_code_virtualization_real as vm_real

FIXTURE = vm_real._DATASET / "elf_vm_interp_stack_x86_64"

_EXPECTED_EXIT_CODE = 45


def _run_pass(dest: Path, *, virtualize_dispatch: bool) -> dict[str, object]:
    binary = Binary(str(dest), writable=True)
    binary.open()
    try:
        config = {"probability": 1.0, "seed": 20260802, "virtualize_dispatch": virtualize_dispatch}
        stats = CodeVirtualizationPass(config=config).apply(binary)
        binary.save()
        return stats
    finally:
        binary.close()


def test_flag_crossing_interpreter_virtualizes_and_preserves_exit_code(tmp_path: Path) -> None:
    """The opt-in dispatch path virtualizes the pushfq/popfq bracket and keeps exit 45."""
    mutated = tmp_path / "flagcross_virtualized"
    shutil.copy(FIXTURE, mutated)
    stats = _run_pass(mutated, virtualize_dispatch=True)
    assert stats["functions_virtualized"] >= 1
    assert vm_real._emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE


def test_flag_crossing_dispatch_left_untouched_without_opt_in(tmp_path: Path) -> None:
    """With the flag off, the computed-jump function - pushfq and all - stays native."""
    mutated = tmp_path / "flagcross_native"
    shutil.copy(FIXTURE, mutated)
    stats = _run_pass(mutated, virtualize_dispatch=False)
    assert stats["functions_virtualized"] == 0
    assert vm_real._emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE
