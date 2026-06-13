"""Binary-region evidence helpers for mutation annotation."""

from __future__ import annotations

from typing import Any


def annotate_binary_region_evidence(mutation_metadata: dict[str, Any], binary_region: dict[str, Any]) -> None:
    """Attach real-binary symbolic verdict + step/exit budget evidence."""
    mutation_metadata["symbolic_binary_check_performed"] = True
    mutation_metadata["symbolic_binary_equivalent"] = len(binary_region.get("mismatches", [])) == 0
    mutation_metadata["symbolic_binary_step_budget"] = int(binary_region.get("step_budget", 1))
    mutation_metadata["symbolic_binary_region_exit_budget"] = int(binary_region.get("region_exit_budget", 0))
    mutation_metadata["symbolic_binary_step_strategy"] = binary_region.get(
        "step_strategy",
        "unknown",
    )
    mutation_metadata["symbolic_binary_original_region_exit_steps"] = int(
        binary_region.get("original_region_exit_steps", 0)
    )
    mutation_metadata["symbolic_binary_mutated_region_exit_steps"] = int(
        binary_region.get("mutated_region_exit_steps", 0)
    )
    mutation_metadata["symbolic_binary_original_region_exit_address"] = binary_region.get(
        "original_region_exit_address"
    )
    mutation_metadata["symbolic_binary_mutated_region_exit_address"] = binary_region.get(
        "mutated_region_exit_address"
    )
    mutation_metadata["symbolic_binary_original_trace_addresses"] = list(
        binary_region.get("original_trace_addresses", [])
    )
    mutation_metadata["symbolic_binary_mutated_trace_addresses"] = list(
        binary_region.get("mutated_trace_addresses", [])
    )
    mutation_metadata["symbolic_binary_mismatches"] = list(binary_region.get("mismatches", []))
    mutation_metadata["symbolic_binary_registers_checked"] = list(binary_region.get("registers_checked", []))
    mutation_metadata["symbolic_binary_control_flow_observables"] = list(
        binary_region.get("control_flow_observables", [])
    )
    mutation_metadata["symbolic_binary_original_memory_writes"] = list(
        binary_region.get("original_memory_writes", [])
    )
    mutation_metadata["symbolic_binary_mutated_memory_writes"] = list(
        binary_region.get("mutated_memory_writes", [])
    )
    mutation_metadata["symbolic_binary_original_memory_write_count"] = int(
        binary_region.get("original_memory_write_count", 0)
    )
    mutation_metadata["symbolic_binary_mutated_memory_write_count"] = int(
        binary_region.get("mutated_memory_write_count", 0)
    )
