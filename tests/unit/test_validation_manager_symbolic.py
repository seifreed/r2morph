"""Characterization of ValidationManager symbolic-helper contracts.

Pins behaviour BEFORE the §6 extraction of a SymbolicValidator
collaborator (CLAUDE.md §5). _collect_memory_write_signatures only
reads attributes off an angr state, so real types.SimpleNamespace
trees exercise every branch faithfully without importing angr.

No mocks / monkeypatch (§4): SimpleNamespace is a concrete value
object, not a unittest.mock.
"""

from __future__ import annotations

from types import SimpleNamespace

from r2morph.validation.manager import ValidationManager


def _mem_write(addr: object, size: object, *, action: str = "write") -> SimpleNamespace:
    return SimpleNamespace(type="mem", action=action, addr=addr, size=size)


def _state(actions: object) -> SimpleNamespace:
    return SimpleNamespace(history=SimpleNamespace(actions=actions))


def test_collect_signatures_no_history_returns_empty() -> None:
    vm = ValidationManager()
    assert (
        vm._symbolic_validator._binary_comparator._collect_memory_write_signatures(SimpleNamespace(history=None)) == []
    )


def test_collect_signatures_actions_none_returns_empty() -> None:
    vm = ValidationManager()
    assert vm._symbolic_validator._binary_comparator._collect_memory_write_signatures(_state(None)) == []


def test_collect_signatures_sorted_deduped_write_and_store() -> None:
    vm = ValidationManager()
    actions = [
        _mem_write(SimpleNamespace(concrete_value=0x2000), SimpleNamespace(concrete_value=4)),
        SimpleNamespace(type="reg", action="write", addr=None, size=None),  # non-mem skipped
        _mem_write(SimpleNamespace(concrete_value=0x1000), SimpleNamespace(concrete_value=8)),
        _mem_write(SimpleNamespace(concrete_value=0x1000), SimpleNamespace(concrete_value=8)),  # dup
        _mem_write(SimpleNamespace(concrete_value=0x3000), SimpleNamespace(concrete_value=1), action="store"),
        SimpleNamespace(type="mem", action="read", addr=None, size=None),  # mem-read skipped
    ]
    assert vm._symbolic_validator._binary_comparator._collect_memory_write_signatures(_state(actions)) == [
        "0x1000:8",
        "0x2000:4",
        "0x3000:1",
    ]


def test_collect_signatures_unconvertible_addr_is_unknown() -> None:
    vm = ValidationManager()
    actions = [_mem_write(SimpleNamespace(concrete_value=object()), SimpleNamespace(concrete_value=8))]
    assert vm._symbolic_validator._binary_comparator._collect_memory_write_signatures(_state(actions)) == ["unknown"]


def test_collect_signatures_missing_size_is_addr_only() -> None:
    vm = ValidationManager()
    actions = [_mem_write(SimpleNamespace(concrete_value=0x4000), None)]
    assert vm._symbolic_validator._binary_comparator._collect_memory_write_signatures(_state(actions)) == ["0x4000"]


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
