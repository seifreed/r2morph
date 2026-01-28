from __future__ import annotations

from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_conditional_jump_detection() -> None:
    pass_obj = ControlFlowFlatteningPass()

    assert pass_obj._is_conditional_jump("je", "x86") is True
    assert pass_obj._is_conditional_jump("beq", "arm") is True
    assert pass_obj._is_conditional_jump("jz", "mips") is True
    assert pass_obj._is_conditional_jump("jmp", "mips") is False


def test_control_flow_flattening_nop_sequence_detection() -> None:
    pass_obj = ControlFlowFlatteningPass()

    instructions = [
        {"offset": 0x1000, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1001, "size": 2, "mnemonic": "nop"},
        {"offset": 0x1003, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1004, "size": 1, "mnemonic": "mov"},
    ]
    assert pass_obj._find_nop_sequences(instructions) == [(0x1000, 4)]

    short_sequence = [
        {"offset": 0x2000, "size": 1, "mnemonic": "nop"},
        {"offset": 0x2001, "size": 1, "mnemonic": "nop"},
        {"offset": 0x2002, "size": 1, "mnemonic": "mov"},
    ]
    assert pass_obj._find_nop_sequences(short_sequence) == []


def test_control_flow_flattening_opaque_predicate_lists() -> None:
    pass_obj = ControlFlowFlatteningPass()

    x86_preds = pass_obj._get_x86_opaque_predicates(64)
    assert len(x86_preds) >= 3
    assert all(isinstance(seq, list) for seq in x86_preds)
    assert all(isinstance(insn, str) for seq in x86_preds for insn in seq)

    arm_preds = pass_obj._get_arm_opaque_predicates(64)
    assert len(arm_preds) >= 1
    assert all(isinstance(seq, list) for seq in arm_preds)
    assert all(isinstance(insn, str) for seq in arm_preds for insn in seq)
