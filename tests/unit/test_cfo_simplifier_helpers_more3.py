from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock


def test_cfo_constant_and_opaque_checks():
    simplifier = CFOSimplifier()
    assert simplifier._is_constant_expression("1", "2") is True
    assert simplifier._is_constant_expression("eax", "eax") is True
    assert simplifier._is_constant_expression("eax", "ebx") is False

    cmp_instr = {
        "opcode": "cmp eax, 0x1",
        "operands": [{"value": "1"}, {"value": "1"}],
    }
    non_cmp = {"opcode": "mov eax, ebx", "operands": []}
    assert simplifier._is_opaque_comparison(cmp_instr) is True
    assert simplifier._is_opaque_comparison(non_cmp) is False


def test_cfo_jump_resolution_and_state_extraction():
    simplifier = CFOSimplifier()
    resolved = simplifier._resolve_jump_target({"opcode": "jmp [32]"})
    assert resolved == 32
    unresolved = simplifier._resolve_jump_target({"opcode": "jmp [eax]"})
    assert unresolved is None

    block = ControlFlowBlock(
        address=0x1000,
        instructions=[
            {"operands": [{"value": "0x10"}]},
            {"operands": [{"value": "8"}]},
        ],
    )
    assert simplifier._extract_state_value(block) == 0x10


def test_cfo_state_setters_and_complexity_fallback():
    simplifier = CFOSimplifier()
    block_a = ControlFlowBlock(
        address=0x2000,
        instructions=[
            {"opcode": "mov state, 3", "operands": [{"value": "state"}, {"value": "3"}]},
        ],
        successors={0x2004, 0x2008},
    )
    block_b = ControlFlowBlock(
        address=0x2004,
        instructions=[],
        successors={0x2008},
    )
    block_c = ControlFlowBlock(address=0x2008, instructions=[], successors=set())
    simplifier.blocks = {block_a.address: block_a, block_b.address: block_b, block_c.address: block_c}
    simplifier.cfg = None

    setters = simplifier._find_state_setters(3, "state")
    assert block_a.address in setters

    assert simplifier._calculate_complexity() == 3
