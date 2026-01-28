from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass


def test_opaque_predicates_apply_real(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        pass_obj = OpaquePredicatePass(
            config={"max_predicates_per_function": 1, "probability": 1.0}
        )
        result = pass_obj.apply(binary)

    assert "mutations_applied" in result
    assert "functions_mutated" in result
    assert result["mutations_applied"] >= 0
