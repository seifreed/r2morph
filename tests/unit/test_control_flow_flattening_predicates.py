from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator


def test_control_flow_flattening_predicate_templates():
    x86_predicates = OpaquePredicateGenerator().get_x86(bits=64)
    assert x86_predicates
    assert all(isinstance(seq, list) for seq in x86_predicates)
    assert any("push" in insn for seq in x86_predicates for insn in seq)

    arm_predicates = OpaquePredicateGenerator().get_arm(bits=64)
    assert arm_predicates
    assert all(isinstance(seq, list) for seq in arm_predicates)
    assert any("mov" in insn for seq in arm_predicates for insn in seq)
