"""The engine VM's per-build arithmetic-fold ISA personality.

The engine only virtualizes flag-dead runs, so its sole personality axis is the
arithmetic fold, shared with the region VM through ``code_virtualization_fold``.
These tests prove the canonical (``engine_isa_seed`` 0) path stays byte-identical
to the pre-feature engine, that the personality diverges per build, and that the
selected variant actually flows into the emitted micro-op handler. The fold's own
value-equivalence vs the CPU is covered by ``test_code_virtualization_isa_arith``.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_engine_isa import build_engine_isa_spec
from r2morph.mutations.code_virtualization_engine_microops import (
    _MNEMONIC_OF,
    MICROOP_BINOP_KINDS,
    microop_handler_body,
)
from r2morph.mutations.code_virtualization_fold import arith_fold
from r2morph.mutations.code_virtualization_mba import _op_mba_compute

_MNEMONICS = ("add", "sub", "xor", "and", "or")
_KEYS = (1, 7, 42, 128, 200, 255)
_ADD_KIND = next(k for k in MICROOP_BINOP_KINDS if _MNEMONIC_OF[k] == "add")


def test_engine_isa_seed_zero_is_canonical() -> None:
    assert build_engine_isa_spec(0).arith_variant == 0


def test_engine_isa_seed_zero_fold_is_byte_identical_to_the_shared_default() -> None:
    variant = build_engine_isa_spec(0).arith_variant
    for mnemonic in _MNEMONICS:
        for key in _KEYS:
            assert arith_fold(mnemonic, key, variant) == _op_mba_compute(mnemonic, key)


def test_engine_isa_seed_diverges_across_builds() -> None:
    variants = {build_engine_isa_spec(seed).arith_variant for seed in range(1, 200)}
    assert len(variants) > 1


def test_arith_variant_flows_into_the_microop_handler() -> None:
    # A non-zero variant must change the emitted fold for at least one build, proving
    # the parameter is threaded through to the handler body (not silently dropped).
    canonical = microop_handler_body(_ADD_KIND, 64, 42, 0x80, 0x88, 0)
    assert any(microop_handler_body(_ADD_KIND, 64, 42, 0x80, 0x88, v) != canonical for v in range(1, 64))
