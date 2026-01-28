from r2morph.mutations.arm_rules import (
    ARM32_EQUIVALENCE_GROUPS,
    ARM64_EQUIVALENCE_GROUPS,
    ARM_THUMB_EQUIVALENCE_GROUPS,
    get_arm_rules,
)


def test_get_arm_rules_selects_arch64():
    rules = get_arm_rules("aarch64", 64)
    assert rules is ARM64_EQUIVALENCE_GROUPS
    assert any("mov x0, #0" in group for group in rules)


def test_get_arm_rules_selects_thumb():
    rules = get_arm_rules("thumb", 32)
    assert rules is ARM_THUMB_EQUIVALENCE_GROUPS
    assert any("movs r0, #0" in group for group in rules)


def test_get_arm_rules_selects_arm32():
    rules = get_arm_rules("arm", 32)
    assert rules is ARM32_EQUIVALENCE_GROUPS
    assert any("mov r0, #0" in group for group in rules)
