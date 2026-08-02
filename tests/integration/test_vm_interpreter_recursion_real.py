"""
Literal recursion: virtualizing a real interpreter's own dispatch loop.

``dataset/elf_vm_interp_reg_x86_64`` is a generic bytecode interpreter whose
dispatch is the classic two-instruction register-indirect form (load the handler
address from the table, jump through the register). Feeding its whole function
through the dispatch-region contract lowers that computed goto to an ``ijmp`` and
builds a target map so the interpreter's own dispatch can re-enter the VM at the
virtualized copy of each handler - literal recursion of the interpreter.

These pin the pieces that are verified end to end on a real binary: the fixture is
a valid interpreter, its whole function extracts into an ``ijmp`` dispatch region
whose target map covers the real handler addresses, and the produced VM interpreter
assembles. The emulated round-trip parity of the mutated binary is the remaining
open step (see docs/vm-literal-recursion.md §5) and is intentionally not asserted
here yet.
"""

from __future__ import annotations

import random

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization_inject import predict_blob_vaddr
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from tests.integration import test_code_virtualization_real as vm_real

FIXTURE = vm_real._DATASET / "elf_vm_interp_reg_x86_64"

_EXPECTED_EXIT_CODE = 45
# The handler-table entries the interpreter's computed jump resolves to at runtime.
_HANDLER_ADDRESSES = {0x1023, 0x102C, 0x1037, 0x1042}


def _whole_function_ops(binary: Binary) -> list[dict[str, object]]:
    """The interpreter's full linear instruction list (r2's function analysis stops
    at the computed jump, so gather linearly to the first terminator)."""
    assert binary.r2 is not None
    ops: list[dict[str, object]] = []
    for insn in binary.r2.cmdj("pdj 40 @ entry0") or []:
        ops.append(insn)
        if insn.get("type") in ("swi", "syscall", "ret"):
            break
    return ops


def _dispatch_region(binary: Binary) -> object:
    binary.analyze("aa")
    return extract_region(_whole_function_ops(binary), random.Random(20260802), allow_computed_jump=True)


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


def test_virtualized_interpreter_blob_assembles() -> None:
    """The VM interpreter for the recursively-virtualized dispatch loop assembles."""
    binary = Binary(str(FIXTURE))
    binary.open()
    try:
        region = _dispatch_region(binary)
        assert region is not None
        rng = random.Random(20260802)
        scheme = build_region_scheme(region, rng)
        assert build_region_blob(region, predict_blob_vaddr(binary), scheme) is not None
    finally:
        binary.close()
