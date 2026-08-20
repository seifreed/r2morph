from __future__ import annotations

import pytest

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier
from r2morph.devirtualization.cfo_simplifier_detection import (
    detect_dispatcher_flattening,
    detect_fake_control_flow,
    detect_indirect_jumps,
    detect_obfuscation_patterns,
    detect_opaque_predicates,
    detect_switch_case_obfuscation,
)
from r2morph.devirtualization.cfo_simplifier_models import CFOPattern, ControlFlowBlock
from tests.utils.assertions import expect


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


def test_detection_helpers_identify_expected_patterns() -> None:
    simplifier = CFOSimplifier()
    simplifier.blocks = {
        0x1000: _block(
            address=0x1000,
            instructions=[
                {"opcode": "cmp eax, eax", "operands": [{"value": "eax"}, {"value": "eax"}]},
                {"opcode": "jmp rax", "operands": []},
            ],
            predecessors={0x10, 0x20, 0x30},
            successors={0x2000, 0x3000, 0x4000, 0x5000},
        ),
        0x2000: _block(address=0x2000, instructions=[{"opcode": "mov eax, eax", "operands": []}]),
        0x3000: _block(address=0x3000, instructions=[{"opcode": "jmp [rax]", "operands": []}]),
        0x4000: _block(address=0x4000, instructions=[{"opcode": "jmp rax", "operands": []}]),
        0x5000: _block(address=0x5000, instructions=[{"opcode": "call [rbx]", "operands": []}]),
    }

    expect(not (detect_dispatcher_flattening(simplifier) is not True))
    expect(not (detect_opaque_predicates(simplifier) is not True))
    expect(not (detect_indirect_jumps(simplifier) is not True))
    expect(not (detect_switch_case_obfuscation(simplifier) is not True))

    patterns = detect_obfuscation_patterns(simplifier)
    expect(not (CFOPattern.DISPATCHER_FLATTENING not in patterns))
    expect(not (CFOPattern.OPAQUE_PREDICATES not in patterns))
    expect(not (CFOPattern.INDIRECT_JUMPS not in patterns))
    expect(not (CFOPattern.SWITCH_CASE_OBFUSCATION not in patterns))


def test_detection_helpers_detect_fake_control_flow_when_cfg_has_unreachable_nodes() -> None:
    nx = pytest.importorskip("networkx")

    simplifier = CFOSimplifier()
    simplifier.blocks = {
        0x1000: _block(address=0x1000, successors={0x2000}),
        0x2000: _block(address=0x2000),
        0x3000: _block(address=0x3000),
    }
    simplifier.cfg = nx.DiGraph()
    simplifier.cfg.add_edges_from([(0x1000, 0x2000)])

    expect(not (detect_fake_control_flow(simplifier) is not True))
