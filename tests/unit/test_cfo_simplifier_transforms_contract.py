from __future__ import annotations

import pytest

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier
from r2morph.devirtualization.cfo_simplifier_models import ControlFlowBlock, DispatcherInfo
from r2morph.devirtualization.cfo_simplifier_transforms import (
    analyze_dispatch_targets,
    calculate_complexity,
    eliminate_opaque_predicates,
    reconstruct_control_flow,
    remove_fake_control_flow,
    resolve_indirect_jumps,
    simplify_dispatcher_flattening,
)
from tests.utils.assertions import expect

_EXPECTED_CALCULATE_COMPLEXITY_SIMPLIFIER_4 = 4
_EXPECTED_SIMPLIFIER_BLOCKS_12288 = 0x3000


def _block(
    *,
    address: int,
    instructions: list[dict[str, object]] | None = None,
    predecessors: set[int] | None = None,
    successors: set[int] | None = None,
) -> ControlFlowBlock:
    return ControlFlowBlock(
        address=address,
        instructions=instructions or [],
        predecessors=predecessors or set(),
        successors=successors or set(),
    )


def test_cfo_simplifier_transform_helpers_apply_expected_changes() -> None:
    simplifier = CFOSimplifier()
    simplifier.blocks = {
        0x1000: _block(
            address=0x1000,
            instructions=[
                {"opcode": "cmp eax, eax", "operands": [{"value": "eax"}, {"value": "eax"}]},
                {"opcode": "jne 0x2000", "operands": []},
                {"opcode": "jmp [12288]", "operands": []},
            ],
            successors={0x2000, 0x3000},
        ),
        0x2000: _block(
            address=0x2000,
            instructions=[{"opcode": "mov state, 1", "operands": [{"value": "state"}, {"value": "1"}]}],
            predecessors={0x1000},
        ),
        0x3000: _block(
            address=0x3000,
            instructions=[{"opcode": "mov state, 2", "operands": [{"value": "state"}, {"value": "2"}]}],
            predecessors={0x1000},
        ),
        0x4000: _block(address=0x4000, successors=set()),
    }
    simplifier.cfg = None
    simplifier.dispatchers = [
        DispatcherInfo(
            dispatcher_address=0x1000,
            state_variable="state",
            dispatch_table={1: 0x2000, 2: 0x3000},
        )
    ]

    dispatcher = simplifier.dispatchers[0]
    analyze_dispatch_targets(simplifier, dispatcher)
    edges = reconstruct_control_flow(simplifier, dispatcher)
    expect((0x1000, 0x2000) not in edges)
    expect(not ((0x2000, 0x2000) not in edges))
    expect(not ((0x3000, 0x3000) not in edges))

    expect(not (simplify_dispatcher_flattening(simplifier) is not True))
    expect(not (eliminate_opaque_predicates(simplifier) is not True))
    expect(not (resolve_indirect_jumps(simplifier) is not True))
    expect(calculate_complexity(simplifier) == _EXPECTED_CALCULATE_COMPLEXITY_SIMPLIFIER_4)

    expect(simplifier.blocks[4096].instructions[0]["opcode"] == "nop")
    expect(simplifier.blocks[4096].instructions[1]["opcode"] == "jmp")
    expect(simplifier.blocks[4096].instructions[2]["opcode"] == "jmp 0x3000")


def test_cfo_simplifier_transform_helpers_remove_unreachable_blocks() -> None:
    nx = pytest.importorskip("networkx")

    simplifier = CFOSimplifier()
    simplifier.blocks = {
        0x1000: _block(address=0x1000, successors={0x2000}),
        0x2000: _block(address=0x2000, successors=set()),
        0x3000: _block(address=0x3000, successors=set()),
    }
    simplifier.cfg = nx.DiGraph()
    simplifier.cfg.add_edges_from([(0x1000, 0x2000)])

    expect(not (remove_fake_control_flow(simplifier) is not True))
    expect(_EXPECTED_SIMPLIFIER_BLOCKS_12288 not in simplifier.blocks)
