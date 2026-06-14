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


def _block(*, address: int, instructions: list[dict[str, object]] | None = None, predecessors: set[int] | None = None, successors: set[int] | None = None) -> ControlFlowBlock:
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

    assert detect_dispatcher_flattening(simplifier) is True
    assert detect_opaque_predicates(simplifier) is True
    assert detect_indirect_jumps(simplifier) is True
    assert detect_switch_case_obfuscation(simplifier) is True

    patterns = detect_obfuscation_patterns(simplifier)
    assert CFOPattern.DISPATCHER_FLATTENING in patterns
    assert CFOPattern.OPAQUE_PREDICATES in patterns
    assert CFOPattern.INDIRECT_JUMPS in patterns
    assert CFOPattern.SWITCH_CASE_OBFUSCATION in patterns


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

    assert detect_fake_control_flow(simplifier) is True
