"""
Unit tests for junk VM-instruction injection in the region lifter.

Identity ``mov reg, reg`` items are sprinkled through the bytecode to pad it with
operations a devirtualizer cannot distinguish from the program's own. They are
semantics-preserving by construction (a slot written with its own value, no
flags), and inserting them must remap every branch target index so control flow
is preserved. End-to-end semantics are covered by the control-flow integration
fixtures; these pin the remap contract on the pure injector.
"""

from __future__ import annotations

import random

from r2morph.mutations.code_virtualization_engine import VirtualizedOp
from r2morph.mutations.code_virtualization_region import _inject_junk_movs


def _items_with_back_branch() -> list[list]:
    # A real mov (dst != src), a conditional branch back to it, and an exit.
    return [
        ["op", VirtualizedOp("mov", 0, 1, False, 64)],
        ["jcc", "jl", 0],
        ["exit", 0x1234],
    ]


def test_injection_adds_identity_mov_items() -> None:
    # A seed that fires the probability adds at least one item, and every added
    # op is an identity mov (dst == src), which is semantics-preserving.
    injected = _inject_junk_movs(_items_with_back_branch(), random.Random(1))
    assert len(injected) > 3
    added = [it for it in injected if it[0] == "op" and it[1].dst_index == it[1].value]
    assert added  # at least one identity-mov junk item


def test_injection_remaps_branch_target_to_the_same_real_item() -> None:
    # After injection the jcc must still target the original first mov (dst=0,
    # src=1), not a shifted or junk position.
    injected = _inject_junk_movs(_items_with_back_branch(), random.Random(1))
    jcc = next(it for it in injected if it[0] == "jcc")
    target = injected[jcc[2]]
    assert target[0] == "op" and target[1].dst_index == 0 and target[1].value == 1


def test_injection_keeps_all_branch_targets_in_range() -> None:
    injected = _inject_junk_movs(_items_with_back_branch(), random.Random(7))
    for item in injected:
        if item[0] == "jmp":
            assert 0 <= item[1] < len(injected)
        elif item[0] == "jcc":
            assert 0 <= item[2] < len(injected)


def test_injection_is_deterministic_for_a_seed() -> None:
    first = _inject_junk_movs(_items_with_back_branch(), random.Random(3))
    second = _inject_junk_movs(_items_with_back_branch(), random.Random(3))
    assert len(first) == len(second)
