from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from tests.utils.assertions import expect


def test_opaque_predicates_apply_real(tmp_path: Path) -> None:
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        pass_obj = OpaquePredicatePass(config={"max_predicates_per_function": 1, "probability": 1.0})
        result = pass_obj.apply(binary)

    expect(not ("mutations_applied" not in result))
    expect(not ("functions_mutated" not in result))
    expect(not (result["mutations_applied"] < 0))
