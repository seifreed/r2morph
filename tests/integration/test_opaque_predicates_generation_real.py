from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass


def test_opaque_predicates_generate_x86_and_arm() -> None:
    x86_path = Path("dataset/elf_x86_64")
    arm_path = Path("dataset/macho_arm64")
    if not x86_path.exists() or not arm_path.exists():
        pytest.skip("Dataset binaries not available")

    pass_obj = OpaquePredicatePass()

    with Binary(x86_path) as bin_x86:
        bin_x86.analyze()
        preds = pass_obj._generate_predicate(bin_x86, "always_true", 0x1000)
        assert preds

    with Binary(arm_path) as bin_arm:
        bin_arm.analyze()
        preds = pass_obj._generate_predicate(bin_arm, "always_false", 0x1000)
        assert preds
