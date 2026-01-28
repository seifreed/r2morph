from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_predicate_templates():
    mutator = ControlFlowFlatteningPass()

    x86_predicates = mutator._get_x86_opaque_predicates(bits=64)
    assert x86_predicates
    assert all(isinstance(seq, list) for seq in x86_predicates)
    assert any("push" in insn for seq in x86_predicates for insn in seq)

    arm_predicates = mutator._get_arm_opaque_predicates(bits=64)
    assert arm_predicates
    assert all(isinstance(seq, list) for seq in arm_predicates)
    assert any("mov" in insn for seq in arm_predicates for insn in seq)
