from r2morph.validation.symbolic_scope_policy import (
    build_scope_metadata,
    check_scope_constraints,
    estimate_symbolic_region_steps,
)
from tests.utils.assertions import expect
from tests.utils.field_names import SYMBOLIC_MUTATION_NAME_KEY

_EXPECTED_ESTIMATE_SYMBOLIC_REGION_STEPS_REGISTERSUBSTI_2 = 2


def test_scope_policy_metadata_and_constraints_round_trip() -> None:
    mutations = [
        {"start_address": "0x401000", "end_address": "0x401003", "function_address": "0x402000"},
        {"start_address": "0x401010", "end_address": "0x401013", "function_address": "0x401000"},
    ]

    metadata = build_scope_metadata(mutations, "InstructionSubstitution")
    expect(metadata["symbolic_backend"] == "angr")
    expect(metadata[SYMBOLIC_MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(metadata["covered_functions"] == [4198400, 4202496])
    expect(metadata["covered_address_ranges"] == [[4198400, 4198403], [4198416, 4198419]])

    expect(
        not (
            check_scope_constraints(
                {"format": "ELF64", "bits": 64, "arch": "x86_64"}, mutations, "InstructionSubstitution"
            )
            is not None
        )
    )
    expect(
        not (
            estimate_symbolic_region_steps(
                "RegisterSubstitution", {"start_address": 0x401000, "end_address": 0x401001, "original_disasm": "nop"}
            )
            < _EXPECTED_ESTIMATE_SYMBOLIC_REGION_STEPS_REGISTERSUBSTI_2
        )
    )
