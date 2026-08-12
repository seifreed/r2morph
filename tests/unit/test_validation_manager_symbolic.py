"""ValidationManager symbolic annotation contracts."""

from __future__ import annotations

from r2morph.validation.manager import ValidationManager


def _instr_sub_pass(mutation: dict[str, object]) -> dict[str, object]:
    return {"pass_name": "InstructionSubstitution", "mutations": [mutation]}


def test_annotate_instruction_substitution_observable_transition_match() -> None:
    vm = ValidationManager()
    mutation: dict[str, object] = {"start_address": 0x1000, "end_address": 0x1010}
    metadata = {
        "symbolic_requested": True,
        "symbolic_status": "checked",
        "symbolic_reason": "ok",
        "symbolic_semantic_hint": "reg-swap",
        "symbolic_semantic_hint_supported": True,
        "symbolic_observable_regions": [
            {"start_address": 0x1000, "end_address": 0x1010, "mismatches": [], "observables_checked": ["rax"]}
        ],
        "symbolic_transition_regions": [{"start_address": 0x1000, "end_address": 0x1010, "mismatches": []}],
    }

    vm._symbolic_validator._mutation_annotator._annotate_mutations_with_symbolic_metadata(
        _instr_sub_pass(mutation), metadata
    )

    md = mutation["metadata"]
    assert md["symbolic_requested"] is True
    assert md["symbolic_status"] == "checked"
    assert md["symbolic_reason"] == "ok"
    assert md["symbolic_semantic_hint"] == "reg-swap"
    assert md["symbolic_semantic_hint_supported"] is True
    assert md["symbolic_observable_check_performed"] is True
    assert md["symbolic_observable_equivalent"] is True
    assert md["symbolic_observable_mismatches"] == []
    assert md["symbolic_observables_checked"] == ["rax"]
    assert md["symbolic_transition_check_performed"] is True
    assert md["symbolic_transition_equivalent"] is True
    assert md["symbolic_transition_mismatches"] == []


def test_annotate_instruction_substitution_observable_key_miss() -> None:
    vm = ValidationManager()
    mutation: dict[str, object] = {"start_address": 0x1000, "end_address": 0x1010}
    metadata = {
        "symbolic_observable_check_performed": True,
        "symbolic_observable_regions": [{"start_address": 0x2000, "end_address": 0x2010, "mismatches": []}],
    }

    vm._symbolic_validator._mutation_annotator._annotate_mutations_with_symbolic_metadata(
        _instr_sub_pass(mutation), metadata
    )

    md = mutation["metadata"]
    assert md["symbolic_observable_check_performed"] is False
    assert md["symbolic_observable_equivalent"] is False
    assert md["symbolic_observable_mismatches"] == []
