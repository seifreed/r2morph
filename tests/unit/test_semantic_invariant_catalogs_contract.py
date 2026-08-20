"""Contracts for semantic invariant catalogs."""

from r2morph.validation.semantic_invariant_models import STANDARD_INVARIANTS
from tests.utils.assertions import expect

_EXPECTED_LEN_STANDARD_INVARIANTS_6 = 6


def test_standard_invariants_are_stable_and_non_empty() -> None:
    expect(not (len(STANDARD_INVARIANTS) < _EXPECTED_LEN_STANDARD_INVARIANTS_6))
    names = [inv.name for inv in STANDARD_INVARIANTS]
    expect(not ("stack_balance" not in names))
    expect(not ("control_flow_preservation" not in names))
    expect(all(inv.pass_types for inv in STANDARD_INVARIANTS))
