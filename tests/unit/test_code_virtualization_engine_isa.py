"""The engine VM's per-build ISA personality (arithmetic fold + address fold).

The engine only virtualizes flag-dead runs, so it has no flag axis: its personality
is the arithmetic fold and, now, the effective-address fold - both shared with the
region VM through ``code_virtualization_fold``. These tests prove the canonical
(``engine_isa_seed`` 0) paths stay byte-identical to the pre-feature engine, that
each personality diverges per build, and that the selected variants actually flow
into the emitted handlers. The folds' own value-equivalence vs the CPU is covered
by ``test_code_virtualization_isa_arith`` and ``test_code_virtualization_isa_addr``.
"""

from __future__ import annotations

import random

from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_isa import build_engine_isa_spec
from r2morph.mutations.code_virtualization_engine_microops import (
    _MNEMONIC_OF,
    MICROOP_BINOP_KINDS,
    microop_handler_body,
)
from r2morph.mutations.code_virtualization_fold import addr_fold, arith_fold
from r2morph.mutations.code_virtualization_mba import _mba_add, _op_mba_compute

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


def test_engine_addr_seed_zero_is_canonical() -> None:
    assert build_engine_isa_spec(0).addr_variant == 0


def test_engine_addr_seed_zero_fold_is_byte_identical_to_mba_add() -> None:
    variant = build_engine_isa_spec(0).addr_variant
    for addend, temp in (("rax", "rcx"), ("r11", "rcx")):
        for key in _KEYS:
            assert addr_fold(addend, temp, key, variant) == _mba_add(addend, temp, key)


def test_engine_addr_variant_diverges_across_builds() -> None:
    variants = {build_engine_isa_spec(seed).addr_variant for seed in range(1, 200)}
    assert len(variants) > 1


def test_addr_variant_flows_into_the_emitted_address_prologue() -> None:
    # Build real engine interpreters until one draws a non-canonical address fold,
    # then assert that build's emitted interpreter carries the variant fold (proving
    # isa.addr_variant reaches the address prologues) and not the canonical one.
    for seed in range(1, 500):
        scheme = build_vm_scheme(random.Random(seed))
        addr_variant = build_engine_isa_spec(scheme.engine_isa_seed).addr_variant
        variant_fold = addr_fold("rax", "rcx", scheme.xor_key, addr_variant)
        canonical_fold = _mba_add("rax", "rcx", scheme.xor_key)
        if addr_variant == 0 or variant_fold == canonical_fold:
            continue
        interpreter = _interpreter_asm(0x1000, scheme)
        assert variant_fold in interpreter, f"seed {seed}: variant address fold not emitted"
        return
    raise AssertionError("no seed produced a divergent engine address fold in range")
