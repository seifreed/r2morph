"""Mutation annotator extracted from SymbolicValidator (clean-arch slice 4a).

Reads a pass-level symbolic metadata dict and writes the per-mutation
symbolic evidence fields back onto each mutation record in place. No
angr, no binary access — fully self-contained (only typing). Imported
lazily by SymbolicValidator.__init__ (composition root).
"""

from __future__ import annotations

from typing import Any

from r2morph.validation.mutation_annotator_binary import annotate_binary_region_evidence
from r2morph.validation.mutation_annotator_instruction import annotate_instruction_substitution_evidence


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
            self._annotate_base_fields(mutation_metadata, metadata)

            key = (mutation["start_address"], mutation["end_address"])
            self._annotate_step_metadata(mutation_metadata, key, stepped_by_range)

            if pass_result.get("pass_name") == "InstructionSubstitution":
                transition_regions = {
                    (region["start_address"], region["end_address"]): region
                    for region in metadata.get("symbolic_transition_regions", [])
                }
                annotate_instruction_substitution_evidence(
                    mutation_metadata,
                    key,
                    metadata,
                    observable_by_range,
                    transition_regions,
                )

            binary_region = binary_by_range.get(key)
            if binary_region is not None:
                annotate_binary_region_evidence(mutation_metadata, binary_region)

    def _annotate_base_fields(
        self,
        mutation_metadata: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """Write the pass-level symbolic verdict fields onto a mutation."""
        mutation_metadata["symbolic_requested"] = bool(metadata.get("symbolic_requested"))
        mutation_metadata["symbolic_status"] = metadata.get("symbolic_status", "unknown")
        mutation_metadata["symbolic_reason"] = metadata.get("symbolic_reason", "")

    def _annotate_step_metadata(
        self,
        mutation_metadata: dict[str, Any],
        key: tuple[Any, Any],
        stepped_by_range: dict[tuple[Any, Any], dict[str, Any]],
    ) -> None:
        """Attach the bounded-step successor evidence for this region, if any."""
        stepped = stepped_by_range.get(key)
        if stepped is not None:
            mutation_metadata["symbolic_step"] = {
                "flat_successors": stepped.get("flat_successors", 0),
                "unsat_successors": stepped.get("unsat_successors", 0),
                "successor_addresses": list(stepped.get("successor_addresses", [])),
            }
