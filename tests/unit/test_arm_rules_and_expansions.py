from r2morph.mutations import arm_rules
from r2morph.mutations import arm_expansion_rules


def test_arm_equivalence_groups_non_empty():
    assert arm_rules.ARM64_EQUIVALENCE_GROUPS
    assert arm_rules.ARM32_EQUIVALENCE_GROUPS
    assert arm_rules.ARM_THUMB_EQUIVALENCE_GROUPS

    for group in arm_rules.ARM64_EQUIVALENCE_GROUPS[:5]:
        assert isinstance(group, list)
        assert len(group) >= 2
        assert all(isinstance(item, str) for item in group)


def test_arm_expansion_rules_lookup_and_conventions():
    arm64_rules = arm_expansion_rules.get_arm_expansion_rules("aarch64", 64)
    thumb_rules = arm_expansion_rules.get_arm_expansion_rules("thumb", 32)
    arm32_rules = arm_expansion_rules.get_arm_expansion_rules("arm", 32)

    assert "nop" in arm64_rules
    assert "nop" in thumb_rules
    assert "nop" in arm32_rules

    arm64_cc = arm_expansion_rules.get_arm_calling_convention("aarch64", 64)
    arm32_cc = arm_expansion_rules.get_arm_calling_convention("arm", 32)

    assert arm64_cc["return_reg"] == "x0"
    assert arm32_cc["return_reg"] == "r0"
    assert "argument_regs" in arm64_cc
    assert "callee_saved" in arm32_cc
