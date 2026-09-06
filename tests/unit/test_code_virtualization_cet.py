"""Contracts for CET landing-pad markers."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from tests.utils.assertions import expect


def test_cet_endbr_markers_are_identity_items() -> None:
    expect(_classify({"type": "null", "opcode": "endbr64"}) == ["nop"])
