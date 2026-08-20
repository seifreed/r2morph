"""
Unit tests for the branch-target guards of region virtualization.

An item index carried by a control-transfer item (``jmp``, ``jcc`` and also
``vcall``, whose operand is an item index exactly like a jump's) must stay valid
through the nested split and the bytecode encoder. These pin the two guards on
real lifter value objects - no mocks, no binary.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen_encode import encode_region
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from r2morph.mutations.code_virtualization_region_nesting import _peel_op_run, split_region
from tests.utils.assertions import expect

_EXIT_VADDR = 0x1010
_ENTRY_VADDR = 0x1000
_BYTECODE_BASE = 0x2000
_CALL_TARGET = 1  # item index the vcall below resolves to


def _items_with_vcall_target_inside_the_op_run() -> list[tuple[Any, ...]]:
    # Items 0..2 are one contiguous eligible run; the vcall resolves to item 1, so a
    # run spanning 0..2 would swallow its target.
    return [
        ("vpush", 0),
        ("vpush", 1),
        ("vpush", 2),
        ("vcall", _CALL_TARGET),
        ("exit", _EXIT_VADDR),
    ]


def _region(items: list[tuple[Any, ...]], target_map: dict[int, int] | None = None) -> Region:
    op_keys = {key for item in items if (key := _op_key(item)) is not None}
    return Region(items, _EXIT_VADDR, _ENTRY_VADDR, op_keys, [], target_map)


def test_peel_op_run_with_vcall_target_inside_the_run_excludes_it_from_the_interior() -> None:
    run = _peel_op_run(_items_with_vcall_target_inside_the_op_run())
    expect(run is not None and _CALL_TARGET not in range(run[0] + 1, run[1]))


def test_split_region_with_a_populated_target_map_returns_none() -> None:
    region = _region(_items_with_vcall_target_inside_the_op_run(), {_ENTRY_VADDR: 0})
    expect(not (split_region(region, randomness.Random(0)) is not None))


def test_encode_region_with_a_negative_branch_target_raises_struct_error() -> None:
    region = _region([("jmp", -1), ("exit", _EXIT_VADDR)])
    scheme = build_region_scheme(region, randomness.Random(0))
    with pytest.raises(struct.error):
        encode_region(region, scheme, _BYTECODE_BASE)
