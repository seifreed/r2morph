"""Mutation annotator extracted from SymbolicValidator (clean-arch slice 4a).

Reads a pass-level symbolic metadata dict and writes the per-mutation
symbolic evidence fields back onto each mutation record in place. No
angr, no binary access — fully self-contained (only typing). Imported
lazily by SymbolicValidator.__init__ (composition root).
"""

from __future__ import annotations

from typing import Any


class MutationAnnotator:
    """Writes pass-level symbolic evidence onto each eligible mutation record."""

    def _annotate_mutations_with_symbolic_metadata(
        self,
        pass_result: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """Attach pass-level symbolic evidence to each eligible mutation record."""
        mutations = pass_result.get("mutations", [])
        if not mutations:
            return

        stepped_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_stepped_regions", [])
        }
        observable_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_observable_regions", [])
        }
        binary_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_binary_regions", [])
        }

        for mutation in mutations:
            mutation_metadata = mutation.setdefault("metadata", {})
            mutation_metadata["symbolic_requested"] = bool(metadata.get("symbolic_requested"))
            mutation_metadata["symbolic_status"] = metadata.get("symbolic_status", "unknown")
            mutation_metadata["symbolic_reason"] = metadata.get("symbolic_reason", "")

            key = (mutation["start_address"], mutation["end_address"])
            stepped = stepped_by_range.get(key)
            if stepped is not None:
                mutation_metadata["symbolic_step"] = {
                    "flat_successors": stepped.get("flat_successors", 0),
                    "unsat_successors": stepped.get("unsat_successors", 0),
                    "successor_addresses": list(stepped.get("successor_addresses", [])),
                }

            if pass_result.get("pass_name") == "InstructionSubstitution":
                mutation_metadata["symbolic_semantic_hint"] = metadata.get("symbolic_semantic_hint", "none")
                mutation_metadata["symbolic_semantic_hint_supported"] = bool(
                    metadata.get("symbolic_semantic_hint_supported", False)
                )

                observable = observable_by_range.get(key)
                if observable is not None:
                    mutation_metadata["symbolic_observable_check_performed"] = True
                    mutation_metadata["symbolic_observable_equivalent"] = len(observable.get("mismatches", [])) == 0
                    mutation_metadata["symbolic_observable_mismatches"] = list(observable.get("mismatches", []))
                    mutation_metadata["symbolic_observables_checked"] = list(observable.get("observables_checked", []))
                elif metadata.get("symbolic_observable_check_performed"):
                    mutation_metadata["symbolic_observable_check_performed"] = False
                    mutation_metadata["symbolic_observable_equivalent"] = False
                    mutation_metadata["symbolic_observable_mismatches"] = []

                transition_regions = {
                    (region["start_address"], region["end_address"]): region
                    for region in metadata.get("symbolic_transition_regions", [])
                }
                transition = transition_regions.get(key)
                if transition is not None:
                    mutation_metadata["symbolic_transition_check_performed"] = True
                    mutation_metadata["symbolic_transition_equivalent"] = len(transition.get("mismatches", [])) == 0
                    mutation_metadata["symbolic_transition_mismatches"] = list(transition.get("mismatches", []))
            binary_region = binary_by_range.get(key)
            if binary_region is not None:
                mutation_metadata["symbolic_binary_check_performed"] = True
                mutation_metadata["symbolic_binary_equivalent"] = len(binary_region.get("mismatches", [])) == 0
                mutation_metadata["symbolic_binary_step_budget"] = int(binary_region.get("step_budget", 1))
                mutation_metadata["symbolic_binary_region_exit_budget"] = int(
                    binary_region.get("region_exit_budget", 0)
                )
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
                mutation_metadata["symbolic_binary_registers_checked"] = list(
                    binary_region.get("registers_checked", [])
                )
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
