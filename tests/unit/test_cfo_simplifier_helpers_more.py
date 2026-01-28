from __future__ import annotations

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock


def test_cfo_simplifier_constant_and_opaque_checks() -> None:
    simplifier = CFOSimplifier()

    assert simplifier._is_constant_expression("1", "2") is True
    assert simplifier._is_constant_expression("eax", "eax") is True
    assert simplifier._is_constant_expression("eax", "ebx") is False

    instr = {"opcode": "cmp eax, eax", "operands": [{"value": "eax"}, {"value": "eax"}]}
    assert simplifier._is_opaque_comparison(instr) is True

    instr_bad = {"opcode": "mov eax, ebx", "operands": [{"value": "eax"}, {"value": "ebx"}]}
    assert simplifier._is_opaque_comparison(instr_bad) is False


def test_cfo_simplifier_resolve_jump_target_and_state_extract() -> None:
    simplifier = CFOSimplifier()

    assert simplifier._resolve_jump_target({"opcode": "jmp [0x10]"}) is None
    assert simplifier._resolve_jump_target({"opcode": "jmp [16]"}) == 16
    assert simplifier._resolve_jump_target({"opcode": "jmp [eax]"}) is None

    block = ControlFlowBlock(
        address=0x1000,
        instructions=[{"operands": [{"value": "0x20"}]}],
    )
    assert simplifier._extract_state_value(block) == 0x20


def test_cfo_simplifier_find_state_setters_and_complexity() -> None:
    simplifier = CFOSimplifier()

    block_a = ControlFlowBlock(
        address=0x1000,
        instructions=[{"opcode": "mov eax, 3", "operands": [{"value": "eax"}, {"value": "3"}]}],
        successors={0x2000},
    )
    block_b = ControlFlowBlock(
        address=0x2000,
        instructions=[{"opcode": "nop"}],
        successors=set(),
    )
    simplifier.blocks = {0x1000: block_a, 0x2000: block_b}

    setters = simplifier._find_state_setters(3, "eax")
    assert 0x1000 in setters

    # Complexity fallback: edge count
    assert simplifier._calculate_complexity() == 1
