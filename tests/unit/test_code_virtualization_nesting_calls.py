"""
Nested (VM-in-VM) virtualization now covers regions that contain calls.

Calls are never peeled into an inner layer, so every call kind stays in the outer
layer where r15 is that layer's bytecode base - the base the direct-call target and
the vcall/vret resume discriminator are already keyed to. With the per-layer
bytecode length threaded to the vret discriminator and a floor cell reserved in the
nested entry, a call-bearing region nests instead of falling back to single-layer.

These pin that the nested builder no longer bails on a direct call or an in-function
call (vcall/vret) and that such a region assembles to real bytes. Runtime parity for
the nested build is covered by the recursion and call fixtures in the integration
suite.
"""

from __future__ import annotations

import random

from r2morph.mutations.code_virtualization_engine import VirtualizedOp
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob

_CAVE_VADDR = 0x500000
_RET_ADDR = 0x2000


def _op_run() -> list[tuple[object, ...]]:
    """Three interchangeable register ops - a peelable run for the inner layer."""
    mov = VirtualizedOp("mov", 0, 1, False, 64)
    return [("op", mov), ("op", mov), ("op", mov)]


def _region(items: list[tuple[object, ...]]) -> Region:
    keys = {k for it in items if (k := _op_key(it)) is not None}
    return Region(items, _RET_ADDR, 0x1000, keys, [(0x1000, 3)])


def test_nested_builder_accepts_an_in_function_call_region() -> None:
    """A region with a peelable run, a vcall and a vret nests to real bytes."""
    items = [*_op_run(), ("vcall", 0), ("vret", _RET_ADDR)]
    blob = build_nested_region_blob(_region(items), _CAVE_VADDR, random.Random(7), depth=2)
    assert blob is not None and len(blob) > 0


def test_nested_builder_accepts_a_direct_call_region() -> None:
    """A region with a peelable run and an out-of-function direct call nests."""
    items = [*_op_run(), ("call", 0x9000), ("exit", _RET_ADDR)]
    blob = build_nested_region_blob(_region(items), _CAVE_VADDR, random.Random(7), depth=2)
    assert blob is not None and len(blob) > 0
