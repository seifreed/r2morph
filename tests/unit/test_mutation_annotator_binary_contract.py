from r2morph.validation.mutation_annotator_binary import annotate_binary_region_evidence
from tests.utils.assertions import expect

_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_REGION_EXIT_4 = 4
_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_STEP_BUDGET_3 = 3


def test_binary_region_evidence_populates_expected_fields() -> None:
    mutation_metadata: dict[str, object] = {}
    annotate_binary_region_evidence(
        mutation_metadata,
        {
            "mismatches": [],
            "step_budget": 3,
            "region_exit_budget": 4,
            "step_strategy": "region-exit",
            "original_region_exit_steps": 1,
            "mutated_region_exit_steps": 2,
            "original_region_exit_address": 0x401010,
            "mutated_region_exit_address": 0x401020,
            "original_trace_addresses": [0x401000, 0x401010],
            "mutated_trace_addresses": [0x401000, 0x401020],
            "registers_checked": ["eax"],
            "control_flow_observables": ["successor_address"],
            "original_memory_writes": ["0x1000:8"],
            "mutated_memory_writes": [],
            "original_memory_write_count": 1,
            "mutated_memory_write_count": 0,
        },
    )

    expect(not (mutation_metadata["symbolic_binary_check_performed"] is not True))
    expect(not (mutation_metadata["symbolic_binary_equivalent"] is not True))
    expect(
        mutation_metadata["symbolic_binary_step_budget"] == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_STEP_BUDGET_3
    )
    expect(
        mutation_metadata["symbolic_binary_region_exit_budget"]
        == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_REGION_EXIT_4
    )
    expect(mutation_metadata["symbolic_binary_step_strategy"] == "region-exit")
    expect(mutation_metadata["symbolic_binary_original_trace_addresses"] == [4198400, 4198416])
    expect(mutation_metadata["symbolic_binary_mutated_memory_write_count"] == 0)
