"""InstructionSubstitution metadata helpers for mutation annotation."""

from __future__ import annotations

from typing import Any


def annotate_instruction_substitution_evidence(
    mutation_metadata: dict[str, Any],
    key: tuple[Any, Any],
    metadata: dict[str, Any],
    observable_by_range: dict[tuple[Any, Any], dict[str, Any]],
    transition_regions: dict[tuple[Any, Any], dict[str, Any]],
) -> None:
    """Attach InstructionSubstitution semantic/observable/transition evidence."""
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

    transition = transition_regions.get(key)
    if transition is not None:
        mutation_metadata["symbolic_transition_check_performed"] = True
        mutation_metadata["symbolic_transition_equivalent"] = len(transition.get("mismatches", [])) == 0
        mutation_metadata["symbolic_transition_mismatches"] = list(transition.get("mismatches", []))
