"""Regression coverage for static RCX-zero branches in the region VM."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from tests.utils.assertions import expect


def test_jrcxz_classifies_as_a_static_region_branch() -> None:
    item = _classify({"type": "cjmp", "opcode": "jrcxz 0x1007", "jump": 0x1007})

    expect(item == ["jrcxz", 0x1007])


def test_jrcxz_region_branch_remaps_and_codegen_succeeds() -> None:
    instructions = [
        {"addr": 0x1000, "size": 2, "type": "cjmp", "opcode": "jrcxz 0x1007", "jump": 0x1007},
        {"addr": 0x1002, "size": 5, "type": "mov", "opcode": "mov rax, 1"},
        {"addr": 0x1007, "size": 1, "type": "ret", "opcode": "ret"},
    ]
    region = extract_region(instructions)
    blob = build_region_blob(region, 0x500000, build_region_scheme(region, randomness.Random(3))) if region else None

    expect(blob is not None and region is not None and region.instructions[0][0] == "jrcxz")
