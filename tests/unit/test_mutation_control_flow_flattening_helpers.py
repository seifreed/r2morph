from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from tests.utils.assertions import expect

_EXPECTED_SIZE_3 = 3
_EXPECTED_START_4096 = 0x1000


def test_control_flow_flattening_helpers():
    pass_obj = ControlFlowFlatteningPass(config={"min_blocks_required": 2})

    expect(not (pass_obj._is_conditional_jump("je", "x86") is not True))
    expect(not (pass_obj._is_conditional_jump("jmp", "x86") is not False))
    expect(not (pass_obj._is_conditional_jump("b.eq", "arm") is not True))
    expect(not (pass_obj._is_conditional_jump("b", "arm") is not False))

    instructions = [
        {"offset": 0x1000, "size": 1, "opcode": "nop"},
        {"offset": 0x1001, "size": 1, "opcode": "nop"},
        {"offset": 0x1002, "size": 1, "opcode": "nop"},
        {"offset": 0x1003, "size": 1, "opcode": "mov"},
    ]
    sequences = pass_obj._find_nop_sequences(instructions)
    expect(sequences)
    start, size = sequences[0]
    expect(start == _EXPECTED_START_4096)
    expect(not (size < _EXPECTED_SIZE_3))

    x86_preds = OpaquePredicateGenerator().get_x86(64)
    arm_preds = OpaquePredicateGenerator().get_arm(64)
    expect(x86_preds)
    expect(arm_preds)
    expect(all(isinstance(seq, list) for seq in x86_preds))
    expect(all(isinstance(seq, list) for seq in arm_preds))
