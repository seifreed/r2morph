from __future__ import annotations

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock
from tests.utils.assertions import expect

_EXPECTED_SETTERS_4096 = 0x1000
_EXPECTED_SIMPLIFIER_EXTRACT_STATE_VALUE_BLOCK_32 = 0x20
_EXPECTED_SIMPLIFIER_RESOLVE_JUMP_TARGET_OPCODE_JMP_16_16 = 16


def test_cfo_simplifier_constant_and_opaque_checks() -> None:
    simplifier = CFOSimplifier()

    expect(not (simplifier._is_constant_expression("1", "2") is not True))
    expect(not (simplifier._is_constant_expression("eax", "eax") is not True))
    expect(not (simplifier._is_constant_expression("eax", "ebx") is not False))

    instr = {"opcode": "cmp eax, eax", "operands": [{"value": "eax"}, {"value": "eax"}]}
    expect(not (simplifier._is_opaque_comparison(instr) is not True))

    instr_bad = {"opcode": "mov eax, ebx", "operands": [{"value": "eax"}, {"value": "ebx"}]}
    expect(not (simplifier._is_opaque_comparison(instr_bad) is not False))


def test_cfo_simplifier_resolve_jump_target_and_state_extract() -> None:
    simplifier = CFOSimplifier()

    expect(not (simplifier._resolve_jump_target({"opcode": "jmp [0x10]"}) is not None))
    expect(
        simplifier._resolve_jump_target({"opcode": "jmp [16]"})
        == _EXPECTED_SIMPLIFIER_RESOLVE_JUMP_TARGET_OPCODE_JMP_16_16
    )
    expect(not (simplifier._resolve_jump_target({"opcode": "jmp [eax]"}) is not None))

    block = ControlFlowBlock(
        address=0x1000,
        instructions=[{"operands": [{"value": "0x20"}]}],
    )
    expect(simplifier._extract_state_value(block) == _EXPECTED_SIMPLIFIER_EXTRACT_STATE_VALUE_BLOCK_32)


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
    expect(not (_EXPECTED_SETTERS_4096 not in setters))

    # Complexity fallback: edge count
    expect(simplifier._calculate_complexity() == 1)
