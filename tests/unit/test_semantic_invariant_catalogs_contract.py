"""Contracts for semantic invariant catalogs."""

from r2morph.validation.semantic_invariant_catalogs import STANDARD_INVARIANTS


def test_standard_invariants_are_stable_and_non_empty() -> None:
    assert len(STANDARD_INVARIANTS) >= 6
    names = [inv.name for inv in STANDARD_INVARIANTS]
    assert "stack_balance" in names
    assert "control_flow_preservation" in names
    assert all(inv.pass_types for inv in STANDARD_INVARIANTS)
