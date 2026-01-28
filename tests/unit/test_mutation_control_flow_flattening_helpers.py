from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_helpers():
    pass_obj = ControlFlowFlatteningPass(config={"min_blocks_required": 2})

    assert pass_obj._is_conditional_jump("je", "x86") is True
    assert pass_obj._is_conditional_jump("jmp", "x86") is False
    assert pass_obj._is_conditional_jump("b.eq", "arm") is True
    assert pass_obj._is_conditional_jump("b", "arm") is False

    instructions = [
        {"offset": 0x1000, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1001, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1002, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1003, "size": 1, "mnemonic": "mov"},
    ]
    sequences = pass_obj._find_nop_sequences(instructions)
    assert sequences
    start, size = sequences[0]
    assert start == 0x1000
    assert size >= 3

    x86_preds = pass_obj._get_x86_opaque_predicates(64)
    arm_preds = pass_obj._get_arm_opaque_predicates(64)
    assert x86_preds
    assert arm_preds
    assert all(isinstance(seq, list) for seq in x86_preds)
    assert all(isinstance(seq, list) for seq in arm_preds)
