import pytest

from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock


def _make_instr(opcode, operands=None):
    return {"opcode": opcode, "operands": operands or []}


def test_cfo_detects_and_eliminates_opaque_predicates():
    simplifier = CFOSimplifier()

    block = ControlFlowBlock(
        address=0x1000,
        instructions=[
            _make_instr("cmp", [{"value": "eax"}, {"value": "eax"}]),
            _make_instr("je", [{"value": "0x2000"}]),
        ],
    )
    simplifier.blocks = {block.address: block}

    assert simplifier._detect_opaque_predicates() is True

    changed = simplifier._eliminate_opaque_predicates()
    assert changed is True
    assert block.instructions[0]["opcode"] == "nop"
    assert block.instructions[1]["opcode"] == "jmp"


def test_cfo_dispatcher_flattening_reconstructs_edges():
    simplifier = CFOSimplifier()

    dispatcher = ControlFlowBlock(
        address=0x100,
        instructions=[
            _make_instr("cmp", [{"value": "state"}, {"value": "1"}]),
            _make_instr("je", [{"value": "0x200"}]),
        ],
        predecessors={0x10, 0x20, 0x30},
        successors={0x200, 0x210},
    )

    target_one = ControlFlowBlock(
        address=0x200,
        instructions=[_make_instr("mov", [{"value": "eax"}, {"value": "1"}])],
    )
    target_two = ControlFlowBlock(
        address=0x210,
        instructions=[_make_instr("mov", [{"value": "eax"}, {"value": "2"}])],
    )

    setter_one = ControlFlowBlock(
        address=0x300,
        instructions=[_make_instr("mov", [{"value": "state"}, {"value": "1"}])],
    )
    setter_two = ControlFlowBlock(
        address=0x310,
        instructions=[_make_instr("mov", [{"value": "state"}, {"value": "2"}])],
    )

    simplifier.blocks = {
        dispatcher.address: dispatcher,
        target_one.address: target_one,
        target_two.address: target_two,
        setter_one.address: setter_one,
        setter_two.address: setter_two,
    }

    assert simplifier._detect_dispatcher_flattening() is True
    assert dispatcher.is_dispatcher is True

    changed = simplifier._simplify_dispatcher_flattening()
    assert changed is True

    assert 0x200 in setter_one.successors
    assert 0x210 in setter_two.successors


def test_cfo_resolves_indirect_jump_and_complexity_fallback():
    simplifier = CFOSimplifier()

    block = ControlFlowBlock(
        address=0x400,
        instructions=[_make_instr("jmp [401000]")],
    )
    simplifier.blocks = {block.address: block}

    assert simplifier._resolve_indirect_jumps() is True
    expected_target = hex(int("401000"))
    assert f"jmp {expected_target}" in block.instructions[0]["opcode"]

    block.successors = {0x500, 0x510}
    assert simplifier._calculate_complexity() == 2
