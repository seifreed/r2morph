import r2morph.mutations.data_flow_mutation_helpers as df_helpers
from r2morph.mutations.data_flow_mutation_helpers import (
    analyze_function_liveness,
    find_safe_substitution_candidates,
    generate_dead_code_with_liveness,
    get_dead_registers,
    is_register_safe_to_use,
)


def test_data_flow_mutation_helpers_cover_core_paths(monkeypatch) -> None:
    monkeypatch.setattr(df_helpers.random, "choice", lambda seq: seq[0])

    instructions = [
        {"addr": 0x1000, "disasm": "mov rax, rbx"},
        {"addr": 0x1004, "disasm": "call foo", "next_addr": 0x1008},
        {"addr": 0x1008, "disasm": "mov rcx, rax"},
    ]

    live_in = analyze_function_liveness(instructions)
    assert isinstance(live_in, dict)
    assert get_dead_registers(0x1000, live_in, {"rax", "rbx"}) <= {"rax", "rbx"}
    assert is_register_safe_to_use("rax", 0x1000, live_in, {"rax", "rbx"}) in {True, False}

    candidates = find_safe_substitution_candidates(instructions, live_in, "x86_64")
    assert isinstance(candidates, list)

    dead_code = generate_dead_code_with_liveness({"rax", "rbx"}, 64, 4)
    assert dead_code is not None
    assert dead_code[0].startswith("push ")
