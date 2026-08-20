from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from tests.utils.assertions import expect


def test_is_conditional_jump_variants():
    pass_obj = ControlFlowFlatteningPass(config={"probability": 1.0})

    expect(not (pass_obj._is_conditional_jump("je", "x86") is not True))
    expect(not (pass_obj._is_conditional_jump("jmp", "x86") is not False))
    expect(not (pass_obj._is_conditional_jump("bne", "arm") is not True))
    expect(not (pass_obj._is_conditional_jump("b", "arm") is not False))

    expect(not (pass_obj._is_conditional_jump("jge", "unknown") is not True))
    expect(not (pass_obj._is_conditional_jump("br", "unknown") is not False))


def test_find_nop_sequences():
    pass_obj = ControlFlowFlatteningPass(config={"probability": 1.0})
    instructions = [
        {"opcode": "nop", "offset": 0x1000, "size": 1},
        {"opcode": "nop", "offset": 0x1001, "size": 1},
        {"opcode": "nop", "offset": 0x1002, "size": 1},
        {"opcode": "mov", "offset": 0x1003, "size": 2},
        {"opcode": "nop", "offset": 0x1005, "size": 1},
        {"opcode": "nop", "offset": 0x1006, "size": 2},
        {"opcode": "nop", "offset": 0x1008, "size": 1},
    ]
    sequences = pass_obj._find_nop_sequences(instructions)
    expect(sequences[0] == (4096, 3))
    expect(sequences[1] == (4101, 4))


def test_arm_opaque_predicate_generation():
    predicates_64 = OpaquePredicateGenerator().get_arm(64)
    predicates_32 = OpaquePredicateGenerator().get_arm(32)

    expect(predicates_64)
    expect(predicates_32)
    expect(any("cmp" in " ".join(seq).lower() for seq in predicates_64))
