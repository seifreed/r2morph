from r2morph.utils.dead_code import (
    generate_x86_dead_code,
    generate_arm_dead_code,
    generate_nop_sequence,
    generate_register_preserving_sequence,
    generate_x86_dead_code_for_size,
    generate_arm_dead_code_for_size,
    generate_dead_code_for_arch,
)


def test_dead_code_generation_x86_and_arm():
    x86_simple = generate_x86_dead_code(bits=64, complexity="simple")
    x86_medium = generate_x86_dead_code(bits=64, complexity="medium")
    x86_complex = generate_x86_dead_code(bits=64, complexity="complex")

    assert isinstance(x86_simple, list)
    assert isinstance(x86_medium, list)
    assert isinstance(x86_complex, list)

    arm_medium = generate_arm_dead_code(bits=32, complexity="medium")
    arm_complex = generate_arm_dead_code(bits=64, complexity="complex")
    assert isinstance(arm_medium, list)
    assert isinstance(arm_complex, list)


def test_nop_and_register_preserving_sequences():
    x86_nops = generate_nop_sequence("x86", 64, 8)
    arm_nops = generate_nop_sequence("arm", 32, 8)

    assert isinstance(x86_nops, (bytes, bytearray))
    assert isinstance(arm_nops, (bytes, bytearray))

    x86_preserve = generate_register_preserving_sequence("x86", 64)
    arm_preserve = generate_register_preserving_sequence("arm", 32)
    assert isinstance(x86_preserve, list)
    assert isinstance(arm_preserve, list)


def test_dead_code_sized_generation_and_arch_dispatch():
    x86_sized = generate_x86_dead_code_for_size(max_size=64, bits=64)
    arm_sized = generate_arm_dead_code_for_size(max_size=64, bits=32)

    assert isinstance(x86_sized, list)
    assert isinstance(arm_sized, list)

    dead_code = generate_dead_code_for_arch("x86", 64, "simple")
    assert isinstance(dead_code, list)
