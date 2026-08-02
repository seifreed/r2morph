"""Per-build arithmetic-fold personality (semantic ISA axis).

Every arithmetic VM handler computes its result with a mixed boolean-arithmetic
rewrite instead of a literal ``add``/``sub``/``xor``/``and``/``or`` (see
:mod:`code_virtualization_mba`). Until now the rewrite was selected coarsely by
``xor_key % len``: the SAME template for every ``add`` in a build, coupled to the
cipher key, so two builds fold identically wherever their keys collide mod the
pool size.

This module gives each build a per-mnemonic, cipher-decoupled fold choice over an
extended pool - the shared templates plus region-local equivalents - so two
samples realize each arithmetic op with different algebra. ``variant`` 0 delegates
verbatim to :func:`_op_mba_compute`, so an ``isa_seed`` of 0 is byte-identical to
the pre-feature output. The extra identities keep the exact calling convention of
the shared builders: they compute ``r10 (op)= rax`` (``add``/``sub`` fold ``r10 +=
rax`` after the handler has negated ``rax`` for ``sub``), preserve ``rax``, clobber
only ``rcx``, and run where their flags are dead.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_mba import (
    _BOOL_VARIANTS,
    _MBA_ADD_TEMPLATES,
    _op_mba_compute,
)

# Region-local add identities (``r10 += {a}``, temp ``{t}``), appended after the
# shared pool so a variant can reach them. Each spans a different instruction shape
# than the shared templates for the same identity (two adds / a doubling add rather
# than an ``lea`` scale), so the fold is not a fixed cross-sample sequence.
_EXTRA_ADD_TEMPLATES: tuple[str, ...] = (
    # a + b == (a ^ b) + 2*(a & b), accumulated with two adds instead of lea*2.
    "  mov {t}, r10\n  and {t}, {a}\n  xor r10, {a}\n  add r10, {t}\n  add r10, {t}\n",
    # a + b == 2*(a | b) - (a ^ b), doubling (a|b) with a self-add instead of lea.
    "  mov {t}, r10\n  xor {t}, {a}\n  or r10, {a}\n  add r10, r10\n  sub r10, {t}\n",
)

# Region-local boolean identities (``r10 = r10 <op> rax``), appended after the
# shared per-op pool. All operate on r10 (a) and rax (b), preserve rax, clobber
# only rcx, and set only dead flags.
_EXTRA_BOOL_VARIANTS: dict[str, tuple[str, ...]] = {
    "xor": (
        # ~(a & b) & (a | b), computing (a|b) then masking with the complement.
        "  mov rcx, r10\n  or rcx, rax\n  and r10, rax\n  not r10\n  and r10, rcx\n",
        # (a + b) - ((a & b) << 1), the carry term doubled with a shift.
        "  mov rcx, r10\n  and rcx, rax\n  shl rcx, 1\n  add r10, rax\n  sub r10, rcx\n",
    ),
    "and": (
        # a - (a & ~b): the bits of a not in b, subtracted away.
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  sub r10, rcx\n",
        # (a | ~b) & b: the second operand masked by the first-or-not-second.
        "  mov rcx, rax\n  not rcx\n  or rcx, r10\n  mov r10, rax\n  and r10, rcx\n",
    ),
    "or": (
        # a + (~a & b): a plus the bits of b it does not already carry.
        "  mov rcx, r10\n  not rcx\n  and rcx, rax\n  add r10, rcx\n",
        # (a & ~b) | b, the disjoint-a term or'd (not added) with b.
        "  mov rcx, rax\n  not rcx\n  and r10, rcx\n  or r10, rax\n",
    ),
}

_ADD_POOL: tuple[str, ...] = _MBA_ADD_TEMPLATES + _EXTRA_ADD_TEMPLATES
_BOOL_POOL: dict[str, tuple[str, ...]] = {
    mnemonic: _BOOL_VARIANTS[mnemonic] + _EXTRA_BOOL_VARIANTS[mnemonic] for mnemonic in _EXTRA_BOOL_VARIANTS
}

# Bits of ``arith_variant`` each mnemonic group reads (3 bits -> up to 8 pool
# entries). add and sub share the add pool; xor/and/or index their own.
_BOOL_SHIFT: dict[str, int] = {"xor": 3, "and": 6, "or": 9}
ARITH_VARIANT_BITS = 12
_GROUP_MASK = 0x7


def arith_fold(mnemonic: str, key: int, variant: int) -> str:
    """Compute ``r10 = r10 <op> rax`` for this build's arithmetic personality.

    ``variant`` 0 returns the canonical, key-selected fold verbatim (byte-identical
    to the pre-feature output). A non-zero ``variant`` selects, per mnemonic and
    independently of ``key``, over the extended pool (shared templates plus the
    region-local identities above), so the fold differs across builds.
    """
    if not variant:
        return _op_mba_compute(mnemonic, key)
    if mnemonic in ("add", "sub"):
        index = (variant & _GROUP_MASK) % len(_ADD_POOL)
        return _ADD_POOL[index].format(a="rax", t="rcx")
    pool = _BOOL_POOL[mnemonic]
    index = ((variant >> _BOOL_SHIFT[mnemonic]) & _GROUP_MASK) % len(pool)
    return pool[index]
