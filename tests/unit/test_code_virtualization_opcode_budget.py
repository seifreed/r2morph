"""Regression: the per-build opcode assignment must always fit the single-byte
dispatch space, no matter how many op-keys exist.

Each op-key draws several interchangeable opcodes; their sum plus an exit marker
must fit in a byte. A micro-op addition once pushed the op-key count high enough
that the summed multiplicity could reach 256, which threw in build_vm_scheme and
silently rolled back the whole virtualization pass. The shed must keep the total
within budget structurally, not by luck of the key count.
"""

from __future__ import annotations

import pytest

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_common import (
    _OPCODE_BUDGET,
    _assign_opcode_multiplicity,
    build_vm_scheme,
)
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_models import Region
from tests.utils.assertions import expect

_EXPECTED_TOTAL_255 = 255


def _region_with_op_keys(op_keys: set[str]) -> Region:
    """A minimal Region carrying only the op-key set the scheme reads."""
    return Region([], 0x1000, 0x1000, op_keys, [])


def test_build_vm_scheme_never_overflows_the_opcode_byte_budget() -> None:
    # Over a wide seed range the assigned indices plus the exit marker always fit a
    # byte: build_vm_scheme must not raise and the exit opcode stays a valid byte
    # at or above the index count.
    for seed in range(3000):
        scheme = build_vm_scheme(randomness.Random(seed))
        total = sum(len(indices) for indices in scheme.dup.values())
        expect(total <= _OPCODE_BUDGET and total <= scheme.exit_opcode <= _EXPECTED_TOTAL_255)


def test_multiplicity_clamps_when_duplication_would_exceed_the_budget() -> None:
    # Almost-budget synthetic op-keys: doubling them all would far exceed the byte
    # space, so the clamp must downgrade duplicated ops until the total fits while
    # never dropping an op below one opcode.
    synthetic = tuple((f"op{i}", False, 64) for i in range(_OPCODE_BUDGET - 10))
    multiplicity = _assign_opcode_multiplicity(synthetic, randomness.Random(1))
    expect(not (sum(multiplicity.values()) > _OPCODE_BUDGET))
    expect(not (min(multiplicity.values()) < 1))


def test_more_op_keys_than_the_budget_raises() -> None:
    # More distinct ops than a byte can index is unrepresentable: fail loud with a
    # typed error rather than silently miscompiling.
    synthetic = tuple((f"op{i}", False, 64) for i in range(_OPCODE_BUDGET + 1))
    with pytest.raises(ValueError, match="opcode budget"):
        _assign_opcode_multiplicity(synthetic, randomness.Random(0))


def test_region_scheme_clamps_when_duplication_would_exceed_the_budget() -> None:
    # The region VM indexes its dispatch table by a single opcode byte too and
    # bounds-guards the exit with `cmp al, handler_count`; near-budget op-keys whose
    # multiplicity would double past the budget must clamp, never overflow the byte.
    region = _region_with_op_keys({f"op_m{i}_r_64" for i in range(_OPCODE_BUDGET - 10)})
    scheme = build_region_scheme(region, randomness.Random(1))
    handler_count = sum(len(indices) for indices in scheme.dup.values())
    expect(not (handler_count > _OPCODE_BUDGET))


def test_region_more_op_keys_than_the_budget_raises() -> None:
    # More distinct region handlers than a byte can index fails loud, not silently.
    region = _region_with_op_keys({f"op_m{i}_r_64" for i in range(_OPCODE_BUDGET + 1)})
    with pytest.raises(ValueError, match="opcode budget"):
        build_region_scheme(region, randomness.Random(0))
