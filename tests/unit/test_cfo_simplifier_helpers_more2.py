from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock


def test_cfo_simplifier_helper_methods():
    simplifier = CFOSimplifier()

    block_a = ControlFlowBlock(
        address=0x1000,
        successors={0x1004, 0x1008},
        instructions=[
            {"opcode": "cmp eax, 5", "operands": [{"value": "5"}, {"value": "5"}]},
        ],
    )
    block_b = ControlFlowBlock(
        address=0x1004,
        successors=set(),
        instructions=[
            {"opcode": "mov state, 5", "operands": [{"value": "state"}, {"value": "5"}]},
        ],
    )
    block_c = ControlFlowBlock(
        address=0x1008,
        successors={0x1004},
        instructions=[
            {"opcode": "mov state, 0x10", "operands": [{"value": "state"}, {"value": "0x10"}]},
        ],
    )

    simplifier.blocks = {block_a.address: block_a, block_b.address: block_b, block_c.address: block_c}

    complexity = simplifier._calculate_complexity()
    assert complexity == 3

    assert simplifier._is_constant_expression("5", "5") is True
    assert simplifier._is_constant_expression("3", "7") is True
    assert simplifier._is_constant_expression("x", "y") is False

    assert simplifier._is_opaque_comparison(block_a.instructions[0]) is True
    assert simplifier._is_opaque_comparison({"opcode": "mov eax, ebx", "operands": []}) is False

    resolved = simplifier._resolve_jump_target({"opcode": "jmp [4096]"})
    assert resolved == 4096

    state_val = simplifier._extract_state_value(block_c)
    assert state_val == 0x10

    setters = simplifier._find_state_setters(5, "state")
    assert block_b.address in setters
