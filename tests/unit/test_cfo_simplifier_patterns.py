import networkx as nx

from r2morph.devirtualization.cfo_simplifier import (
    CFOSimplifier,
    ControlFlowBlock,
    CFOPattern,
)


def _make_block(address, instructions, predecessors=None, successors=None):
    return ControlFlowBlock(
        address=address,
        instructions=instructions,
        predecessors=set(predecessors or []),
        successors=set(successors or []),
    )


def test_cfo_pattern_detection_and_simplification():
    simplifier = CFOSimplifier(binary=None)

    dispatcher = _make_block(
        0x100,
        instructions=[
            {"opcode": "cmp", "operands": [{"value": "state"}, {"value": "1"}]},
            {"opcode": "je", "operands": [{"value": "0x200"}]},
            {"opcode": "cmp", "operands": [{"value": "state"}, {"value": "2"}]},
            {"opcode": "jne", "operands": [{"value": "0x300"}]},
            {"opcode": "jmp", "operands": [{"value": "0x400"}]},
        ],
        predecessors=[0x200, 0x300, 0x400],
        successors=[0x200, 0x300, 0x400],
    )

    block_200 = _make_block(
        0x200,
        instructions=[
            {"opcode": "mov", "operands": [{"value": "state"}, {"value": "1"}]},
            {"opcode": "jmp", "operands": [{"value": "0x100"}]},
        ],
        predecessors=[0x100],
        successors=[0x100],
    )

    block_300 = _make_block(
        0x300,
        instructions=[
            {"opcode": "mov", "operands": [{"value": "state"}, {"value": "2"}]},
            {"opcode": "jmp", "operands": [{"value": "0x100"}]},
        ],
        predecessors=[0x100],
        successors=[0x100],
    )

    block_400 = _make_block(
        0x400,
        instructions=[
            {"opcode": "jmp [4096]"},
        ],
        predecessors=[0x100],
        successors=[],
    )

    opaque_block = _make_block(
        0x500,
        instructions=[
            {"opcode": "cmp", "operands": [{"value": "eax"}, {"value": "eax"}]},
            {"opcode": "je", "operands": [{"value": "0x600"}]},
        ],
        predecessors=[],
        successors=[],
    )

    simplifier.blocks = {
        0x100: dispatcher,
        0x200: block_200,
        0x300: block_300,
        0x400: block_400,
        0x500: opaque_block,
    }

    cfg = nx.DiGraph()
    for addr in simplifier.blocks:
        cfg.add_node(addr)
    cfg.add_edge(0x100, 0x200)
    cfg.add_edge(0x100, 0x300)
    cfg.add_edge(0x100, 0x400)
    cfg.add_edge(0x200, 0x100)
    cfg.add_edge(0x300, 0x100)
    simplifier.cfg = cfg

    patterns = simplifier._detect_obfuscation_patterns()
    assert CFOPattern.DISPATCHER_FLATTENING in patterns
    assert CFOPattern.INDIRECT_JUMPS in patterns
    assert CFOPattern.OPAQUE_PREDICATES in patterns
    assert CFOPattern.FAKE_CONTROL_FLOW in patterns

    assert simplifier._simplify_dispatcher_flattening() is True
    assert simplifier._eliminate_opaque_predicates() is True
    assert simplifier._resolve_indirect_jumps() is True
    assert simplifier._remove_fake_control_flow() is True
