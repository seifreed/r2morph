"""
Unit tests for nested (multi-layer) region virtualization.

The split must move a contiguous register-op run out of the outer stream into an
inner layer reached by ``enter_inner`` and returning through ``inner_exit``,
without any branch target crossing the boundary. These pin the split contract on
the real lifter (no mocks, no binary).
"""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_nesting import (
    _MAX_LAYERS,
    _RETURN_BASE,
    _build_layers,
    _peel_op_run,
    _relayer_sharing_frame,
    build_nested_region_blob,
    split_region,
)


def _region_with_op_run() -> Any:
    # Two register ops then a terminator: the ops form a peelable run.
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov edi, 0x2a", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "add", "opcode": "add edi, 0x3", "size": 3, "jump": -1},
        {"addr": 0x1008, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x100D, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    assert region is not None
    return region


def test_peel_op_run_finds_the_register_op_block() -> None:
    region = _region_with_op_run()
    run = _peel_op_run(region.instructions)
    assert run is not None
    start, end = run
    # The arithmetic op is lowered to virtual-stack micro-ops before peeling, so the
    # register block is a contiguous run of ops and their micro-op primitives.
    peelable = ("op", "opmba", "opsynth", "vpush", "vpop", "vpushi", "vbinop", "vbinopsynth")
    assert all(region.instructions[i][0] in peelable for i in range(start, end))
    assert end - start >= 2


def test_split_region_moves_op_run_to_inner_layer() -> None:
    outer, inner = split_region(_region_with_op_run(), random.Random(0))
    assert [item[0] for item in outer.instructions].count("enter_inner") == 1
    assert inner.instructions[-1][0] == "inner_exit"


def test_split_region_keeps_terminator_in_outer_layer() -> None:
    outer, inner = split_region(_region_with_op_run(), random.Random(0))
    assert any(item[0] == "exit" for item in outer.instructions)
    assert all(item[0] != "exit" for item in inner.instructions)


def _two_distinct_layer_schemes() -> Any:
    # Two schemes drawn from the same rng stream get their own personalities, the
    # per-layer diversity the nested reconstruction must preserve.
    region = _region_with_op_run()
    rng = random.Random(1234)
    schemes = [build_region_scheme(region, rng) for _ in range(2)]
    assert schemes[0].isa_seed != schemes[1].isa_seed
    assert schemes[0].body_seed != schemes[1].body_seed
    return schemes


def test_relayer_sharing_frame_preserves_per_layer_isa_seed() -> None:
    schemes = _two_distinct_layer_schemes()
    relayered = _relayer_sharing_frame(schemes, schemes[0].slot_perm)
    assert [s.isa_seed for s in relayered] == [s.isa_seed for s in schemes]


def test_relayer_sharing_frame_preserves_per_layer_body_seed() -> None:
    schemes = _two_distinct_layer_schemes()
    relayered = _relayer_sharing_frame(schemes, schemes[0].slot_perm)
    assert [s.body_seed for s in relayered] == [s.body_seed for s in schemes]


def test_relayer_sharing_frame_shares_one_slot_permutation() -> None:
    schemes = _two_distinct_layer_schemes()
    shared = schemes[0].slot_perm
    relayered = _relayer_sharing_frame(schemes, shared)
    assert all(s.slot_perm == shared for s in relayered)


def test_split_region_returns_none_without_a_peelable_run() -> None:
    # A single op between terminators is too short to peel.
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    assert region is not None
    assert split_region(region, random.Random(0)) is None


def _region_with_long_op_run() -> Any:
    # A run of flag-dead register arithmetic (each add's flags are overwritten by
    # the trailing cmp before the branch reads them) lowers to many virtual-stack
    # micro-ops, so the run is long enough to peel recursively into three or more
    # independently-keyed layers rather than a single inner one.
    instructions = [
        {"addr": 0x1000, "type": "add", "opcode": "add eax, ebx", "size": 3, "jump": -1},
        {"addr": 0x1003, "type": "add", "opcode": "add eax, ecx", "size": 3, "jump": -1},
        {"addr": 0x1006, "type": "add", "opcode": "add eax, edx", "size": 3, "jump": -1},
        {"addr": 0x1009, "type": "add", "opcode": "add eax, esi", "size": 3, "jump": -1},
        {"addr": 0x100C, "type": "cmp", "opcode": "cmp eax, edi", "size": 3, "jump": -1},
        {"addr": 0x100F, "type": "cjmp", "opcode": "jne 0x1000", "size": 2, "jump": 0x1000, "fail": 0x1011},
        {"addr": 0x1011, "type": "ret", "opcode": "ret", "size": 1, "jump": -1},
    ]
    region = extract_region(instructions, random.Random(1))
    assert region is not None
    return region


def test_build_layers_at_depth_three_yields_three_layers() -> None:
    layers = _build_layers(_region_with_long_op_run(), 3, random.Random(7))
    assert layers is not None and len(layers) == 3


def test_build_layers_at_depth_four_yields_four_layers() -> None:
    layers = _build_layers(_region_with_long_op_run(), 4, random.Random(7))
    assert layers is not None and len(layers) == 4


def test_build_nested_region_blob_at_depth_three_assembles() -> None:
    blob = build_nested_region_blob(_region_with_long_op_run(), 0x401000, random.Random(7), depth=3)
    assert blob is not None and len(blob) > 0


def test_build_nested_region_blob_at_depth_four_assembles() -> None:
    blob = build_nested_region_blob(_region_with_long_op_run(), 0x401000, random.Random(7), depth=4)
    assert blob is not None and len(blob) > 0


def test_return_slot_budget_at_max_layers_fits_below_red_zone() -> None:
    # Each of the up-to-_MAX_LAYERS parent->child transitions reserves one qword
    # return slot at _RETURN_BASE + index*8; the whole run must stay below the
    # preserved red zone at 0x100 so a return pointer never clobbers it.
    assert _RETURN_BASE + _MAX_LAYERS * 8 <= 0x100
