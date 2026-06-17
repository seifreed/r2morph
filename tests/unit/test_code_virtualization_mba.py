"""
Unit tests for the mixed-boolean-arithmetic (MBA) address computation.

The shared address prologues fold the displacement with one of several
equivalent MBA identities (chosen per instance) instead of a literal ``add``, so
the handler's address arithmetic is neither a plain pattern nor a single fixed
MBA signature. Semantics are covered by the memory fixtures; these tests pin the
obfuscation form and its polymorphism on the real builders.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_handlers import (
    _MBA_ADD_VARIANTS,
    _indexed_address_asm,
    _mba_add_r10_rax,
    _mem_address_asm,
)


def test_no_address_prologue_uses_a_literal_displacement_add() -> None:
    for key in range(1, 256):
        for asm in (
            _mem_address_asm(False, key, "0x6c6c6c6c")[0],
            _mem_address_asm(True, key, "0x6c6c6c6c")[0],
            _indexed_address_asm(key, "0x6c6c6c6c")[0],
        ):
            assert "add r10, rax" not in asm


def test_displacement_fold_is_one_of_the_known_mba_variants() -> None:
    for key in range(1, 256):
        assert _mba_add_r10_rax(key) in _MBA_ADD_VARIANTS


def test_mba_variant_is_polymorphic_across_instances() -> None:
    # Different bytecode keys must be able to select different folds, so the MBA
    # is not a single fixed pattern across samples.
    produced = {_mba_add_r10_rax(key) for key in range(1, 256)}
    assert len(produced) == len(_MBA_ADD_VARIANTS) > 1
