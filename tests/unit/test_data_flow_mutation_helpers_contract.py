import r2morph.mutations.data_flow_mutation_helpers as df_helpers
from r2morph.mutations.data_flow_mutation_helpers import (
    analyze_function_liveness,
    find_safe_substitution_candidates,
    generate_dead_code_with_liveness,
    get_dead_registers,
    is_register_safe_to_use,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_DEAD_CODE_4 = 4


def test_data_flow_mutation_helpers_cover_core_paths() -> None:
    df_helpers.random.seed(42)

    instructions = [
        {"addr": 0x1000, "disasm": "mov rax, rbx"},
        {"addr": 0x1004, "disasm": "call foo", "next_addr": 0x1008},
        {"addr": 0x1008, "disasm": "mov rcx, rax"},
    ]

    live_in = analyze_function_liveness(instructions)
    expect(isinstance(live_in, dict))
    expect(not (get_dead_registers(0x1000, live_in, {"rax", "rbx"}) > {"rax", "rbx"}))
    expect(not (is_register_safe_to_use("rax", 0x1000, live_in, {"rax", "rbx"}) not in {True, False}))

    candidates = find_safe_substitution_candidates(instructions, live_in, "x86_64")
    expect(isinstance(candidates, list))

    dead_code = generate_dead_code_with_liveness({"rax", "rbx"}, 64, 4)
    expect(dead_code is not None)
    expect(not (len(dead_code) > _EXPECTED_LEN_DEAD_CODE_4))


def test_candidates_rename_only_dead_register_destinations() -> None:
    instructions = [
        {"addr": 0x2000, "next_addr": 0x2004, "disasm": "mov rax, rcx"},
        {"addr": 0x2004, "next_addr": 0, "disasm": "ret"},
    ]
    live_in = {0x2000: {"rax", "rcx"}, 0x2004: set()}

    candidates = find_safe_substitution_candidates(instructions, live_in, "x86_64")

    expect(
        len(candidates) == 1
        and candidates[0][0] is instructions[0]
        and candidates[0][1] == "rax"
        and candidates[0][2] not in {"rax", "rcx"}
    )
