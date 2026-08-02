"""
Literal recursion: virtualizing a real interpreter's own dispatch loop.

``dataset/elf_vm_interp_reg_x86_64`` is a generic bytecode interpreter whose
dispatch is the classic two-instruction register-indirect form (load the handler
address from the table, jump through the register). Feeding its whole function
through the dispatch-region contract lowers that computed goto to an ``ijmp`` and
builds a target map so the interpreter's own dispatch re-enters the VM at the
virtualized copy of each handler - literal recursion of the interpreter.

These drive the full round trip on a real binary: the whole function extracts into
an ``ijmp`` region whose target map covers the real handler addresses, the produced
VM interpreter assembles, injects, and is patched in, and the mutated binary - now
running a virtualized copy of its own fetch/decode/dispatch cycle - still emulates
to the interpreter's original exit code.
"""

from __future__ import annotations

import random
import shutil
import struct
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization_inject import inject_blob, predict_blob_vaddr
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from r2morph.mutations.code_virtualization_region_models import Region
from tests.integration import test_code_virtualization_real as vm_real

FIXTURE = vm_real._DATASET / "elf_vm_interp_reg_x86_64"

_EXPECTED_EXIT_CODE = 45
_TRAMPOLINE_SIZE = 5
# The handler-table entries the interpreter's computed jump resolves to at runtime.
_HANDLER_ADDRESSES = {0x1023, 0x102C, 0x1037, 0x1042}


def _whole_function_ops(binary: Binary) -> list[dict[str, object]]:
    """The interpreter's full linear instruction list (r2's function analysis stops
    at the computed jump, so gather linearly to the first terminator)."""
    assert binary.r2 is not None
    ops: list[dict[str, object]] = []
    for insn in binary.r2.cmdj("pdj 40 @ entry0") or []:
        if insn.get("type") == "ill" or insn.get("opcode") == "invalid":
            continue
        ops.append(insn)
        if insn.get("type") in ("swi", "syscall", "ret"):
            break
    return ops


def _dispatch_region(binary: Binary, rng: random.Random) -> Region | None:
    binary.analyze("aa")
    return extract_region(_whole_function_ops(binary), rng, allow_computed_jump=True)


def _recursively_virtualize(dest: Path, seed: int) -> None:
    """Virtualize the interpreter's own dispatch loop in ``dest`` in place."""
    rng = random.Random(seed)
    binary = Binary(str(dest), writable=True)
    binary.open()
    try:
        region = _dispatch_region(binary, rng)
        assert region is not None
        blob_vaddr = predict_blob_vaddr(binary)
        assert blob_vaddr is not None
        scheme = build_region_scheme(region, rng)
        blob = build_region_blob(region, blob_vaddr, scheme)
        assert blob is not None
        injected = inject_blob(binary, blob)
        assert injected == blob_vaddr
        relative = injected - (region.entry_vaddr + _TRAMPOLINE_SIZE)
        binary.write_bytes(region.entry_vaddr, b"\xe9" + struct.pack("<i", relative))
        trampoline_end = region.entry_vaddr + _TRAMPOLINE_SIZE
        for addr, size in region.body_ranges:
            fill_start = max(addr, trampoline_end)
            fill_size = addr + size - fill_start
            if fill_size > 0:
                binary.write_bytes(fill_start, bytes(random.randrange(256) for _ in range(fill_size)))
        binary.save()
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
        region = _dispatch_region(binary, random.Random(1))
        assert region is not None and any(item[0] == "ijmp" for item in region.instructions)
    finally:
        binary.close()


def test_dispatch_target_map_covers_the_handler_addresses() -> None:
    """The target map contains every handler the computed jump resolves to."""
    binary = Binary(str(FIXTURE))
    binary.open()
    try:
        region = _dispatch_region(binary, random.Random(1))
        assert region is not None and _HANDLER_ADDRESSES <= set(region.target_map)
    finally:
        binary.close()


def test_recursively_virtualized_interpreter_preserves_exit_code(tmp_path: Path) -> None:
    """Virtualizing the interpreter's own dispatch loop preserves its result (exit 45).

    This is the literal-recursion acceptance: the mutated binary executes a
    virtualized copy of its own fetch/decode/dispatch cycle and still interprets its
    bytecode to the same exit code.
    """
    mutated = tmp_path / "recursively_virtualized"
    shutil.copy(FIXTURE, mutated)
    _recursively_virtualize(mutated, seed=20260802)
    assert vm_real._emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE
