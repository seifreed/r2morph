"""Contracts for invariant data models."""

from r2morph.analysis.invariant_models import Invariant, InvariantType
from tests.utils.assertions import expect


def test_invariant_repr_and_enum_values() -> None:
    inv = Invariant(
        invariant_type=InvariantType.STACK_BALANCE,
        description="Stack must balance",
        location=0x401000,
        details={"depth": 0},
    )

    expect(repr(inv) == "<Invariant stack_balance @ 0x401000: Stack must balance>")
    expect(InvariantType.REGISTER_PRESERVATION.value == "reg_preserve")
    expect(InvariantType.MEMORY_SAFETY.value == "memory_safety")
