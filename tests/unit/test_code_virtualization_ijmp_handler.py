"""
The ijmp runtime handler and its target map: a computed jump re-enters the VM.

When a virtualized computed-goto interpreter executes its own dispatch jump, the
target is a native handler address whose bytes the virtualizer has overwritten. The
ijmp handler therefore does not leave to that address; it looks the target up in a
runtime map (native address -> bytecode offset) baked into the blob and commits the
matching offset to the virtual instruction pointer, re-entering the VM at the
virtualized copy of the target handler.

These pin the structural contract: the map is built from ``Region.target_map`` with
offsets that mirror the encoder, the interpreter assembles cleanly with the handler
and map present, and an ordinary region (no computed jump) emits no map at all.
Runtime semantic parity is covered by the recursion round-trip in the integration
suite.
"""

from __future__ import annotations

import random

from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_codegen_encode import build_ijmp_targets
from r2morph.mutations.code_virtualization_region_models import Region

_CAVE_VADDR = 0x500000


def _ijmp_region() -> Region:
    """A minimal region: a computed jump whose target maps to the exit item."""
    return Region(
        instructions=[("ijmp", 0), ("exit", 0x2000)],
        exit_vaddr=0x2000,
        entry_vaddr=0x1000,
        op_keys={"ijmp", "exit_8192"},
        body_ranges=[(0x1010, 2)],
        target_map={0x1017: 1},
    )


def test_build_ijmp_targets_pairs_native_address_with_encoder_offset() -> None:
    """A target address maps to the bytecode offset of its item (ijmp size 2)."""
    # Item 0 (ijmp) occupies offset 0..1, so item 1 (the target) starts at offset 2.
    assert build_ijmp_targets(_ijmp_region()) == [(0x1017, 2)]


def test_build_ijmp_targets_empty_without_target_map() -> None:
    """A region with no computed jumps produces no map (its blob is unchanged)."""
    plain = Region([("exit", 0x2000)], 0x2000, 0x1000, {"exit_8192"}, [])
    assert build_ijmp_targets(plain) == []


def test_ijmp_interpreter_assembles_with_handler_and_map() -> None:
    """The interpreter with an ijmp handler and target map assembles to real bytes."""
    region = _ijmp_region()
    scheme = build_region_scheme(region, random.Random(1234))
    assert build_region_blob(region, _CAVE_VADDR, scheme) is not None


def test_ijmp_interpreter_emits_target_map_section() -> None:
    """The assembled interpreter carries the runtime map keyed by the target's delta
    from the map label (base-independent; see the dedicated regression module)."""
    region = _ijmp_region()
    scheme = build_region_scheme(region, random.Random(1234))
    asm = _interpreter_asm(region, scheme)
    assert "ijmp_map:" in asm and f"  .quad ijmp_map - {0x1017}\n" in asm


def test_ordinary_region_emits_no_target_map_section() -> None:
    """Without a computed jump the interpreter emits no map label at all."""
    plain = Region([("exit", 0x2000)], 0x2000, 0x1000, {"exit_8192"}, [])
    scheme = build_region_scheme(plain, random.Random(1234))
    assert "ijmp_map:" not in _interpreter_asm(plain, scheme)
