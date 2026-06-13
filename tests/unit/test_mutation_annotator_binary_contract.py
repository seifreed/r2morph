from r2morph.validation.mutation_annotator_binary import annotate_binary_region_evidence


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

    assert mutation_metadata["symbolic_binary_check_performed"] is True
    assert mutation_metadata["symbolic_binary_equivalent"] is True
    assert mutation_metadata["symbolic_binary_step_budget"] == 3
    assert mutation_metadata["symbolic_binary_region_exit_budget"] == 4
    assert mutation_metadata["symbolic_binary_step_strategy"] == "region-exit"
    assert mutation_metadata["symbolic_binary_original_trace_addresses"] == [0x401000, 0x401010]
    assert mutation_metadata["symbolic_binary_mutated_memory_write_count"] == 0
