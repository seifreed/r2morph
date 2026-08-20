from __future__ import annotations

from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from tests.utils.assertions import expect

_EXPECTED_LEN_X86_PREDS_3 = 3


def test_control_flow_flattening_conditional_jump_detection() -> None:
    pass_obj = ControlFlowFlatteningPass()

    expect(not (pass_obj._is_conditional_jump("je", "x86") is not True))
    expect(not (pass_obj._is_conditional_jump("beq", "arm") is not True))
    expect(not (pass_obj._is_conditional_jump("jz", "mips") is not True))
    expect(not (pass_obj._is_conditional_jump("jmp", "mips") is not False))


def test_control_flow_flattening_nop_sequence_detection() -> None:
    pass_obj = ControlFlowFlatteningPass()

    instructions = [
        {"offset": 0x1000, "size": 1, "opcode": "nop"},
        {"offset": 0x1001, "size": 2, "opcode": "nop"},
        {"offset": 0x1003, "size": 1, "opcode": "nop"},
        {"offset": 0x1004, "size": 1, "opcode": "mov"},
    ]
    expect(pass_obj._find_nop_sequences(instructions) == [(4096, 4)])

    short_sequence = [
        {"offset": 0x2000, "size": 1, "opcode": "nop"},
        {"offset": 0x2001, "size": 1, "opcode": "nop"},
        {"offset": 0x2002, "size": 1, "opcode": "mov"},
    ]
    expect(pass_obj._find_nop_sequences(short_sequence) == [])


def test_control_flow_flattening_opaque_predicate_lists() -> None:
    x86_preds = OpaquePredicateGenerator().get_x86(64)
    expect(not (len(x86_preds) < _EXPECTED_LEN_X86_PREDS_3))
    expect(all(isinstance(seq, list) for seq in x86_preds))
    expect(all(isinstance(insn, str) for seq in x86_preds for insn in seq))

    arm_preds = OpaquePredicateGenerator().get_arm(64)
    expect(not (len(arm_preds) < 1))
    expect(all(isinstance(seq, list) for seq in arm_preds))
    expect(all(isinstance(insn, str) for seq in arm_preds for insn in seq))
