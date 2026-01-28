from __future__ import annotations

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock


def test_cfo_simplifier_detects_dispatcher_and_patterns() -> None:
    simplifier = CFOSimplifier()

    dispatcher = ControlFlowBlock(
        address=0x1000,
        instructions=[
            {
                "opcode": "cmp eax, 1",
                "operands": [{"value": "eax"}, {"value": "1"}],
            }
        ],
        predecessors={0x2000, 0x3000, 0x4000},
        successors={0x2000, 0x3000},
    )
    target_one = ControlFlowBlock(
        address=0x2000,
        instructions=[{"operands": [{"value": "1"}]}],
        successors=set(),
    )
    target_two = ControlFlowBlock(
        address=0x3000,
        instructions=[{"operands": [{"value": "2"}]}],
        successors=set(),
    )
    simplifier.blocks = {
        0x1000: dispatcher,
        0x2000: target_one,
        0x3000: target_two,
    }

    assert simplifier._detect_dispatcher_flattening() is True
    assert simplifier.dispatchers
    assert simplifier.blocks[0x1000].is_dispatcher is True

    patterns = simplifier._detect_obfuscation_patterns()
    assert patterns


def test_cfo_simplifier_opaque_indirect_and_switch_detection() -> None:
    simplifier = CFOSimplifier()

    opaque_block = ControlFlowBlock(
        address=0x4000,
        instructions=[
            {
                "opcode": "cmp eax, eax",
                "operands": [{"value": "eax"}, {"value": "eax"}],
            }
        ],
        successors=set(),
    )
    indirect_block = ControlFlowBlock(
        address=0x5000,
        instructions=[{"opcode": "jmp [eax]"}],
        successors=set(),
    )
    switch_block = ControlFlowBlock(
        address=0x6000,
        instructions=[{"opcode": "jmp rax"}],
        successors={0x7000, 0x7001, 0x7002, 0x7003},
    )
    simplifier.blocks = {
        0x4000: opaque_block,
        0x5000: indirect_block,
        0x6000: switch_block,
    }

    assert simplifier._detect_opaque_predicates() is True
    assert simplifier._detect_indirect_jumps() is True
    assert simplifier._detect_switch_case_obfuscation() is True


def test_cfo_simplifier_eliminate_and_resolve_jumps() -> None:
    simplifier = CFOSimplifier()

    opaque_jump_block = ControlFlowBlock(
        address=0x8000,
        instructions=[
            {
                "opcode": "cmp eax, eax",
                "operands": [{"value": "eax"}, {"value": "eax"}],
            },
            {"opcode": "je 0x9000"},
        ],
        successors={0x9000},
    )
    indirect_jump_block = ControlFlowBlock(
        address=0x9000,
        instructions=[{"opcode": "jmp [16]"}],
        successors=set(),
    )
    simplifier.blocks = {
        0x8000: opaque_jump_block,
        0x9000: indirect_jump_block,
    }

    assert simplifier._eliminate_opaque_predicates() is True
    assert opaque_jump_block.instructions[0]["opcode"] == "nop"
    assert opaque_jump_block.instructions[1]["opcode"] == "jmp"

    assert simplifier._resolve_indirect_jumps() is True
    assert indirect_jump_block.instructions[0]["opcode"] == "jmp 0x10"
