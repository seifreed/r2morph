from __future__ import annotations

from r2morph.utils.dead_code import (
    generate_arm_dead_code,
    generate_arm_dead_code_for_size,
    generate_dead_code_for_arch,
    generate_nop_sequence,
    generate_register_preserving_sequence,
    generate_x86_dead_code,
    generate_x86_dead_code_for_size,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_ARM_NOPS_8 = 8


def test_dead_code_generators_x86() -> None:
    simple = generate_x86_dead_code(64, "simple")
    medium = generate_x86_dead_code(64, "medium")
    complex_seq = generate_x86_dead_code(64, "complex")

    expect(simple and medium and complex_seq)
    expect(all(isinstance(ins, str) for ins in simple))

    small = generate_x86_dead_code_for_size(4, 64)
    mid = generate_x86_dead_code_for_size(8, 64)
    large = generate_x86_dead_code_for_size(16, 64)
    expect(small and mid and large)


def test_dead_code_generators_arm() -> None:
    simple = generate_arm_dead_code(64, "simple")
    medium = generate_arm_dead_code(64, "medium")
    complex_seq = generate_arm_dead_code(64, "complex")

    expect(simple and medium and complex_seq)

    small = generate_arm_dead_code_for_size(4, 64)
    mid = generate_arm_dead_code_for_size(8, 64)
    large = generate_arm_dead_code_for_size(12, 64)
    expect(small and mid and large)


def test_dead_code_misc_helpers() -> None:
    x86_nops = generate_nop_sequence("x86", 64, 5)
    arm_nops = generate_nop_sequence("arm", 64, 8)
    unknown_nops = generate_nop_sequence("mips", 32, 3)

    expect(x86_nops == b"\x90" * 5)
    expect(len(arm_nops) == _EXPECTED_LEN_ARM_NOPS_8)
    expect(unknown_nops == b"\x00" * 3)

    x86_preserve = generate_register_preserving_sequence("x86", 64)
    arm_preserve = generate_register_preserving_sequence("arm", 64)
    expect(x86_preserve and arm_preserve)

    fallback = generate_dead_code_for_arch("mips", 32, "simple")
    expect(fallback)
