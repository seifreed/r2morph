from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from tests.utils.assertions import expect


def test_control_flow_flattening_predicate_templates():
    x86_predicates = OpaquePredicateGenerator().get_x86(bits=64)
    expect(x86_predicates)
    expect(all(isinstance(seq, list) for seq in x86_predicates))
    expect(any("push" in insn for seq in x86_predicates for insn in seq))

    arm_predicates = OpaquePredicateGenerator().get_arm(bits=64)
    expect(arm_predicates)
    expect(all(isinstance(seq, list) for seq in arm_predicates))
    expect(any("mov" in insn for seq in arm_predicates for insn in seq))
