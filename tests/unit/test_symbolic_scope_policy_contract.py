from r2morph.validation.symbolic_scope_policy import (
    build_scope_metadata,
    check_scope_constraints,
    estimate_symbolic_region_steps,
)


def test_scope_policy_metadata_and_constraints_round_trip() -> None:
    mutations = [
        {"start_address": "0x401000", "end_address": "0x401003", "function_address": "0x402000"},
        {"start_address": "0x401010", "end_address": "0x401013", "function_address": "0x401000"},
    ]

    metadata = build_scope_metadata(mutations, "InstructionSubstitution")
    assert metadata["symbolic_backend"] == "angr"
    assert metadata["symbolic_pass_name"] == "InstructionSubstitution"
    assert metadata["covered_functions"] == [0x401000, 0x402000]
    assert metadata["covered_address_ranges"] == [[0x401000, 0x401003], [0x401010, 0x401013]]

    assert (
        check_scope_constraints({"format": "ELF64", "bits": 64, "arch": "x86_64"}, mutations, "InstructionSubstitution")
        is None
    )
    assert estimate_symbolic_region_steps(
        "RegisterSubstitution", {"start_address": 0x401000, "end_address": 0x401001, "original_disasm": "nop"}
    ) >= 2
