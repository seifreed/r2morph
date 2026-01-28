from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_is_conditional_jump_variants():
    pass_obj = ControlFlowFlatteningPass(config={"probability": 1.0})

    assert pass_obj._is_conditional_jump("je", "x86") is True
    assert pass_obj._is_conditional_jump("jmp", "x86") is False
    assert pass_obj._is_conditional_jump("bne", "arm") is True
    assert pass_obj._is_conditional_jump("b", "arm") is False

    assert pass_obj._is_conditional_jump("jge", "unknown") is True
    assert pass_obj._is_conditional_jump("br", "unknown") is False


def test_find_nop_sequences():
    pass_obj = ControlFlowFlatteningPass(config={"probability": 1.0})
    instructions = [
        {"mnemonic": "nop", "offset": 0x1000, "size": 1},
        {"mnemonic": "nop", "offset": 0x1001, "size": 1},
        {"mnemonic": "nop", "offset": 0x1002, "size": 1},
        {"mnemonic": "mov", "offset": 0x1003, "size": 2},
        {"mnemonic": "nop", "offset": 0x1005, "size": 1},
        {"mnemonic": "nop", "offset": 0x1006, "size": 2},
        {"mnemonic": "nop", "offset": 0x1008, "size": 1},
    ]
    sequences = pass_obj._find_nop_sequences(instructions)
    assert sequences[0] == (0x1000, 3)
    assert sequences[1] == (0x1005, 4)


def test_arm_opaque_predicate_generation():
    pass_obj = ControlFlowFlatteningPass(config={"probability": 1.0})
    predicates_64 = pass_obj._get_arm_opaque_predicates(64)
    predicates_32 = pass_obj._get_arm_opaque_predicates(32)

    assert predicates_64
    assert predicates_32
    assert any("cmp" in " ".join(seq).lower() for seq in predicates_64)
