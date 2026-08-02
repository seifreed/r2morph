"""
Literal recursion: virtualizing a real interpreter's own dispatch loop.

``dataset/elf_vm_interp_reg_x86_64`` is a generic bytecode interpreter whose
dispatch is the classic two-instruction register-indirect form (load the handler
address from the table, jump through the register). The opt-in dispatch-region
contract lowers that computed goto to an ``ijmp`` and builds a target map so the
interpreter's own dispatch re-enters the VM at the virtualized copy of each handler
- literal recursion of the interpreter.

These drive the real pass on a real binary: with ``virtualize_dispatch`` enabled the
whole function extracts into an ``ijmp`` region and the mutated binary - now running
a virtualized copy of its own fetch/decode/dispatch cycle - still emulates to the
interpreter's original exit code. With the flag off (the default) the dispatch
function is left untouched.
"""

from __future__ import annotations

import random
import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_models import Region
from tests.integration import test_code_virtualization_real as vm_real

FIXTURE = vm_real._DATASET / "elf_vm_interp_reg_x86_64"

_EXPECTED_EXIT_CODE = 45
# The handler-table entries the interpreter's computed jump resolves to at runtime.
_HANDLER_ADDRESSES = {0x1023, 0x102C, 0x1037, 0x1042}


def _dispatch_region(binary: Binary) -> Region | None:
    """Extract the interpreter's whole function under the dispatch-region contract.

    r2's function analysis stops at the computed jump, so gather linearly to the
    first terminator (the same window the pass uses)."""
    assert binary.r2 is not None
    binary.analyze("aa")
    ops: list[dict[str, object]] = []
    for insn in binary.r2.cmdj("pdj 40 @ entry0") or []:
        if insn.get("type") == "invalid" or insn.get("opcode") == "invalid":
            continue
        ops.append(insn)
        if insn.get("type") in ("swi", "syscall", "ret"):
            break
    return extract_region(ops, random.Random(1), allow_computed_jump=True)


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


def test_interpreter_fixture_emulates_to_expected_exit_code() -> None:
    """The register-dispatch interpreter is valid: its bytecode program exits 45."""
    assert vm_real._emulate_exit_code(FIXTURE) == _EXPECTED_EXIT_CODE


def test_interpreter_dispatch_lowers_to_a_computed_jump_region() -> None:
    """The whole interpreter function extracts into a region with an ijmp item."""
    binary = Binary(str(FIXTURE))
    binary.open()
    try:
        region = _dispatch_region(binary)
        assert region is not None and any(item[0] == "ijmp" for item in region.instructions)
    finally:
        binary.close()


def test_dispatch_target_map_covers_the_handler_addresses() -> None:
    """The target map contains every handler the computed jump resolves to."""
    binary = Binary(str(FIXTURE))
    binary.open()
    try:
        region = _dispatch_region(binary)
        assert region is not None and _HANDLER_ADDRESSES <= set(region.target_map)
    finally:
        binary.close()


def test_recursively_virtualized_interpreter_preserves_exit_code(tmp_path: Path) -> None:
    """Virtualizing the interpreter's own dispatch loop preserves its result (exit 45).

    The literal-recursion acceptance: with the dispatch contract enabled, the pass
    replaces the interpreter's fetch/decode/dispatch cycle with a virtualized copy,
    and the mutated binary still interprets its bytecode to the same exit code.
    """
    mutated = tmp_path / "recursively_virtualized"
    shutil.copy(FIXTURE, mutated)
    stats = _run_pass(mutated, virtualize_dispatch=True)
    assert stats["functions_virtualized"] >= 1
    assert vm_real._emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE


def test_dispatch_function_left_untouched_without_opt_in(tmp_path: Path) -> None:
    """The default pass does not virtualize a dispatch-shaped function."""
    mutated = tmp_path / "default"
    shutil.copy(FIXTURE, mutated)
    stats = _run_pass(mutated, virtualize_dispatch=False)
    assert stats["functions_virtualized"] == 0
    assert vm_real._emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE
