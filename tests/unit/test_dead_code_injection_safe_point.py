from r2morph.core.constants import UNCONDITIONAL_TRANSFERS
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from tests.utils.assertions import expect


def test_dead_code_injection_safe_point_unconditional():
    pass_obj = DeadCodeInjectionPass()

    instructions = [
        {"opcode": "jmp"},
        {"opcode": "nop"},
    ]

    expect(not ("jmp" not in UNCONDITIONAL_TRANSFERS))
    expect(not (pass_obj._is_safe_injection_point(instructions[1], instructions, 1) is not True))

    # Non-padding after unconditional should be unsafe
    instructions2 = [
        {"opcode": "ret"},
        {"opcode": "mov"},
    ]
    expect(not (pass_obj._is_safe_injection_point(instructions2[1], instructions2, 1) is not False))
