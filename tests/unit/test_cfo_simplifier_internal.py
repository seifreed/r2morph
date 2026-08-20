from r2morph.devirtualization.cfo_simplifier import CFOSimplifier, ControlFlowBlock
from tests.utils.assertions import expect

_EXPECTED_SETTER_ONE_SUCCESSORS_512 = 0x200
_EXPECTED_SETTER_TWO_SUCCESSORS_528 = 0x210
_EXPECTED_SIMPLIFIER_CALCULATE_COMPLEXITY_2 = 2


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

    expect(not (simplifier._detect_opaque_predicates() is not True))

    changed = simplifier._eliminate_opaque_predicates()
    expect(not (changed is not True))
    expect(block.instructions[0]["opcode"] == "nop")
    expect(block.instructions[1]["opcode"] == "jmp")


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

    expect(not (simplifier._detect_dispatcher_flattening() is not True))
    expect(not (dispatcher.is_dispatcher is not True))

    changed = simplifier._simplify_dispatcher_flattening()
    expect(not (changed is not True))

    expect(not (_EXPECTED_SETTER_ONE_SUCCESSORS_512 not in setter_one.successors))
    expect(not (_EXPECTED_SETTER_TWO_SUCCESSORS_528 not in setter_two.successors))


def test_cfo_resolves_indirect_jump_and_complexity_fallback():
    simplifier = CFOSimplifier()

    block = ControlFlowBlock(
        address=0x400,
        instructions=[_make_instr("jmp [401000]")],
    )
    simplifier.blocks = {block.address: block}

    expect(not (simplifier._resolve_indirect_jumps() is not True))
    expected_target = hex(int("401000"))
    expect(not (f"jmp {expected_target}" not in block.instructions[0]["opcode"]))

    block.successors = {0x500, 0x510}
    expect(simplifier._calculate_complexity() == _EXPECTED_SIMPLIFIER_CALCULATE_COMPLEXITY_2)
