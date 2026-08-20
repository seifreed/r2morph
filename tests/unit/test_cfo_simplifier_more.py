import importlib

import pytest

from r2morph.devirtualization.cfo_simplifier import NETWORKX_AVAILABLE, CFOSimplifier, ControlFlowBlock
from tests.utils.assertions import expect

_EXPECTED_SIMPLIFIER_BLOCKS_768 = 0x300
_EXPECTED_SIMPLIFIER_EXTRACT_STATE_VALUE_BLOCK_16 = 16


@pytest.mark.skipif(not NETWORKX_AVAILABLE, reason="NetworkX not available")
def test_cfo_fake_control_flow_detection_and_removal():
    simplifier = CFOSimplifier()

    entry = ControlFlowBlock(address=0x100, successors={0x200})
    reachable = ControlFlowBlock(address=0x200)
    unreachable = ControlFlowBlock(address=0x300)

    simplifier.blocks = {
        entry.address: entry,
        reachable.address: reachable,
        unreachable.address: unreachable,
    }

    nx = importlib.import_module("networkx")

    simplifier.cfg = nx.DiGraph()
    simplifier.cfg.add_edge(entry.address, reachable.address)
    simplifier.cfg.add_node(unreachable.address)

    expect(not (simplifier._detect_fake_control_flow() is not True))
    expect(not (simplifier._remove_fake_control_flow() is not True))
    expect(_EXPECTED_SIMPLIFIER_BLOCKS_768 not in simplifier.blocks)


def test_cfo_extract_state_and_setters():
    simplifier = CFOSimplifier()

    block = ControlFlowBlock(
        address=0x500,
        instructions=[
            {"opcode": "mov", "operands": [{"value": "eax"}, {"value": "0x10"}]},
            {"opcode": "mov", "operands": [{"value": "state"}, {"value": "3"}]},
        ],
    )
    setter = ControlFlowBlock(
        address=0x600,
        instructions=[{"opcode": "mov", "operands": [{"value": "state"}, {"value": "3"}]}],
    )

    simplifier.blocks = {block.address: block, setter.address: setter}

    expect(simplifier._extract_state_value(block) == _EXPECTED_SIMPLIFIER_EXTRACT_STATE_VALUE_BLOCK_16)
    setters = simplifier._find_state_setters(3, "state")
    expect(not (setter.address not in setters))


def test_cfo_constant_expression_and_opaque_comparison():
    simplifier = CFOSimplifier()

    expect(not (simplifier._is_constant_expression("4", "4") is not True))
    expect(not (simplifier._is_constant_expression("4", "5") is not True))
    expect(not (simplifier._is_constant_expression("eax", "ebx") is not False))

    instr = {"opcode": "cmp", "operands": [{"value": "1"}, {"value": "1"}]}
    expect(not (simplifier._is_opaque_comparison(instr) is not True))
