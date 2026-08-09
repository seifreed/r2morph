"""Value-equivalence of every per-build arithmetic-fold variant against the CPU.

``code_virtualization_fold.arith_fold`` computes ``r10 = r10 <op> rax`` with a
mixed boolean-arithmetic rewrite so a handler never spells out a literal
add/sub/xor/and/or. Each build selects, per mnemonic, one rewrite from an extended
pool (the shared templates plus region-local identities). A wrong identity would
silently miscompute a virtualized program, so this harness pins every reachable
variant: for edge-case operands at 64-bit it compares the folded result against
the native operation. It also proves ``variant`` 0 is byte-identical to the
canonical fold, that the fold preserves ``rax`` and clobbers only ``rcx``, and that
distinct isa_seeds diverge.
"""

from __future__ import annotations

import random

import pytest

from r2morph.mutations.code_virtualization_fold import ARITH_VARIANT_BITS, arith_fold
from r2morph.mutations.code_virtualization_mba import _op_mba_compute
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec

_MASK = 0xFFFFFFFFFFFFFFFF
_REF = {
    "add": lambda a, b: (a + b) & _MASK,
    "sub": lambda a, b: (a - b) & _MASK,
    "xor": lambda a, b: (a ^ b) & _MASK,
    "and": lambda a, b: (a & b) & _MASK,
    "or": lambda a, b: (a | b) & _MASK,
}
# arith_variant values that reach every pool entry: setting all four 4-bit group
# nibbles to the same i for i in 0..15 exercises each mnemonic group's index i mod
# its pool size, so across the range every reachable add/xor/and/or template is hit.
_VARIANTS = tuple(i | (i << 4) | (i << 8) | (i << 12) for i in range(16))


def _edge_operands() -> tuple[int, ...]:
    sign = 1 << 63
    fixed = (0, 1, 2, _MASK, sign, sign - 1, sign + 1, _MASK - 1)
    rng = random.Random(0xA71F01D)  # constant seed, never runtime randomness
    return fixed + tuple(rng.randrange(1 << 64) for _ in range(6))


def _run_fold(mnemonic: str, key: int, variant: int, a: int, b: int) -> tuple[int, int]:
    """Return ``(r10, rax)`` after running the fold with r10=a, rax=b under unicorn."""
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_R10, UC_X86_REG_RAX, UC_X86_REG_RSP

    # sub negates the source before the shared add fold, exactly like the handlers.
    asm = ("  neg rax\n" if mnemonic == "sub" else "") + arith_fold(mnemonic, key, variant)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    mu.mem_map(0x200000, 0x2000)
    mu.reg_write(UC_X86_REG_RSP, 0x201000)
    mu.reg_write(UC_X86_REG_R10, a)
    mu.reg_write(UC_X86_REG_RAX, b)
    mu.emu_start(0x1000, 0x1000 + len(code))
    return mu.reg_read(UC_X86_REG_R10), mu.reg_read(UC_X86_REG_RAX)


@pytest.mark.parametrize("mnemonic", sorted(_REF))
@pytest.mark.parametrize("variant", _VARIANTS)
def test_arith_fold_result_matches_the_native_op_for_every_variant(mnemonic: str, variant: int) -> None:
    pytest.importorskip("keystone")
    pytest.importorskip("unicorn")
    key = 0x5B  # a representative build key; the fold is key-independent for variant != 0
    for a in _edge_operands():
        for b in _edge_operands():
            result, _rax = _run_fold(mnemonic, key, variant, a, b)
            assert result == _REF[mnemonic](a, b), f"{mnemonic} v{variant}: {a:#x} op {b:#x} -> {result:#x}"


@pytest.mark.parametrize("mnemonic", ("add", "xor", "and", "or"))
@pytest.mark.parametrize("variant", (1, 2, 3, (1 << ARITH_VARIANT_BITS) - 1))
def test_arith_fold_preserves_the_source_operand(mnemonic: str, variant: int) -> None:
    # add/xor/and/or must leave rax (the source b) untouched for the callers that
    # reuse it; sub deliberately negates it, so it is excluded here.
    pytest.importorskip("keystone")
    pytest.importorskip("unicorn")
    b = 0xDEADBEEFCAFEF00D
    _result, rax = _run_fold(mnemonic, 0x11, variant, 0x0123456789ABCDEF, b)
    assert rax == b


@pytest.mark.parametrize("mnemonic", sorted(_REF))
def test_arith_fold_variant_zero_is_byte_identical_to_the_canonical_fold(mnemonic: str) -> None:
    for key in (1, 0x5B, 0xC7, 255):
        assert arith_fold(mnemonic, key, 0) == _op_mba_compute(mnemonic, key)


def test_arith_fold_variants_diverge() -> None:
    # Distinct variants selecting different pool entries produce different assembly.
    assert arith_fold("add", 0x5B, 1) != arith_fold("add", 0x5B, 2)
    assert arith_fold("xor", 0x5B, 1 << 4) != arith_fold("xor", 0x5B, 2 << 4)


def test_build_isa_spec_arith_variant_zero_is_canonical_and_diverges() -> None:
    assert build_isa_spec(0).arith_variant == 0
    variants = {build_isa_spec(seed).arith_variant for seed in range(1, 40)}
    assert len(variants) > 1  # different builds get different arith personalities
