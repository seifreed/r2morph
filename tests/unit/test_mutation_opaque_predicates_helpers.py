from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from tests.utils.assertions import expect


def test_opaque_predicate_generators():
    pass_obj = OpaquePredicatePass()
    x86_pred = pass_obj._generate_x86_predicate("always_true", 64)
    arm_pred = pass_obj._generate_arm_predicate("always_false", 64)

    expect(isinstance(x86_pred, list))
    expect(isinstance(arm_pred, list))
    expect(x86_pred)
    expect(arm_pred)


def test_opaque_predicate_apply_real_binary(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "opaque_pred"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = OpaquePredicatePass(config={"max_predicates_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    expect(not ("mutations_applied" not in result))
