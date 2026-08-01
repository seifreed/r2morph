"""Regression: the per-build opcode assignment must always fit the single-byte
dispatch space, no matter how many op-keys exist.

Each op-key draws one or two interchangeable opcodes; their sum plus an exit
marker must fit in a byte. A micro-op addition once pushed the op-key count high
enough that the summed multiplicity could reach 256, which threw in
build_vm_scheme and silently rolled back the whole virtualization pass. The clamp
must keep the total within budget structurally, not by luck of the key count.
"""

from __future__ import annotations

import random

import pytest

from r2morph.mutations.code_virtualization_engine_common import (
    _OPCODE_BUDGET,
    _assign_opcode_multiplicity,
    build_vm_scheme,
)


def test_build_vm_scheme_never_overflows_the_opcode_byte_budget() -> None:
    # Over a wide seed range the assigned indices plus the exit marker always fit a
    # byte: build_vm_scheme must not raise and the exit opcode stays a valid byte
    # at or above the index count.
    for seed in range(3000):
        scheme = build_vm_scheme(random.Random(seed))
        total = sum(len(indices) for indices in scheme.dup.values())
        assert total <= _OPCODE_BUDGET and total <= scheme.exit_opcode <= 255


def test_multiplicity_clamps_when_duplication_would_exceed_the_budget() -> None:
    # Almost-budget synthetic op-keys: doubling them all would far exceed the byte
    # space, so the clamp must downgrade duplicated ops until the total fits while
    # never dropping an op below one opcode.
    synthetic = tuple((f"op{i}", False, 64) for i in range(_OPCODE_BUDGET - 10))
    multiplicity = _assign_opcode_multiplicity(synthetic, random.Random(1))
    assert sum(multiplicity.values()) <= _OPCODE_BUDGET
    assert min(multiplicity.values()) >= 1


def test_more_op_keys_than_the_budget_raises() -> None:
    # More distinct ops than a byte can index is unrepresentable: fail loud with a
    # typed error rather than silently miscompiling.
    synthetic = tuple((f"op{i}", False, 64) for i in range(_OPCODE_BUDGET + 1))
    with pytest.raises(ValueError, match="opcode budget"):
        _assign_opcode_multiplicity(synthetic, random.Random(0))
