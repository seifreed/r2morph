"""ValidationManager symbolic annotation contracts."""

from __future__ import annotations

from r2morph.validation.manager import ValidationManager
from tests.utils.assertions import expect


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
    expect(not (md["symbolic_requested"] is not True))
    expect(md["symbolic_status"] == "checked")
    expect(md["symbolic_reason"] == "ok")
    expect(md["symbolic_semantic_hint"] == "reg-swap")
    expect(not (md["symbolic_semantic_hint_supported"] is not True))
    expect(not (md["symbolic_observable_check_performed"] is not True))
    expect(not (md["symbolic_observable_equivalent"] is not True))
    expect(md["symbolic_observable_mismatches"] == [])
    expect(md["symbolic_observables_checked"] == ["rax"])
    expect(not (md["symbolic_transition_check_performed"] is not True))
    expect(not (md["symbolic_transition_equivalent"] is not True))
    expect(md["symbolic_transition_mismatches"] == [])


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
    expect(not (md["symbolic_observable_check_performed"] is not False))
    expect(not (md["symbolic_observable_equivalent"] is not False))
    expect(md["symbolic_observable_mismatches"] == [])
