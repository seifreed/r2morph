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
    _mba_add,
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
    # a + b == 2*(a | b) - (a ^ b), doubling (a|b) with a shift instead of a self-add.
    "  mov {t}, r10\n  xor {t}, {a}\n  or r10, {a}\n  shl r10, 1\n  sub r10, {t}\n",
    # a + b == -(~a) - 1 + b: rebuild a from its complement (a = -(~a) - 1), then add b,
    # so the fold needs no scratch register at all.
    "  not r10\n  neg r10\n  sub r10, 1\n  add r10, {a}\n",
    # a + b == (a & b) + (a | b), the AND/OR half-adder terms in the opposite order
    # from the shared template (or first, then the and into the accumulator).
    "  mov {t}, r10\n  or {t}, {a}\n  and r10, {a}\n  add r10, {t}\n",
    # a + b == a - (-b): negate the addend and subtract, reaching the sum through a
    # subtraction rather than any add.
    "  mov {t}, {a}\n  neg {t}\n  sub r10, {t}\n",
    # a + b == (a ^ b) + 2*(a & b), doubling the AND term with lea rather than a shift.
    "  mov {t}, r10\n  and {t}, {a}\n  lea {t}, [{t} + {t}]\n  xor r10, {a}\n  add r10, {t}\n",
    # a + b == b - ~a - 1: rebuild through the addend, subtracting the complement of a.
    "  mov {t}, r10\n  not {t}\n  mov r10, {a}\n  sub r10, {t}\n  sub r10, 1\n",
    # a + b == 2*(a | b) - (a ^ b), accumulated in the temp then moved back.
    "  mov {t}, r10\n  or {t}, {a}\n  add {t}, {t}\n  xor r10, {a}\n  sub {t}, r10\n  mov r10, {t}\n",
    # a + b == ~(~a - b): a double complement around a subtraction, needing no temp.
    "  not r10\n  sub r10, {a}\n  not r10\n",
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
        # 2*(a | b) - (a + b), the OR doubled and the sum subtracted back off.
        "  mov rcx, r10\n  or rcx, rax\n  add rcx, rcx\n  add r10, rax\n  sub rcx, r10\n  mov r10, rcx\n",
        # (a & ~b) + (~a & b), the two disjoint half-terms of the XOR summed (no carry
        # can occur between them, so the add equals an or/xor here).
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  not r10\n  and r10, rax\n  add r10, rcx\n",
        # ~((a & b) | ~(a | b)): the complement of the "both-equal" mask is the XOR.
        "  mov rcx, r10\n  or rcx, rax\n  not rcx\n  and r10, rax\n  or r10, rcx\n  not r10\n",
        # (a | b) - (a & b), forming the AND term first (commuted from the base form).
        "  mov rcx, rax\n  and rcx, r10\n  or r10, rax\n  sub r10, rcx\n",
        # (a + b) - ((a & b) << 1), the carry term doubled with a self-add.
        "  mov rcx, r10\n  and rcx, rax\n  add rcx, rcx\n  add r10, rax\n  sub r10, rcx\n",
    ),
    "and": (
        # a - (a & ~b): the bits of a not in b, subtracted away.
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  sub r10, rcx\n",
        # a ^ (a & ~b): removing the bits of a absent from b leaves the AND.
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  xor r10, rcx\n",
        # (a | b) - (a ^ b), forming the XOR term first (commuted from the base form).
        "  mov rcx, rax\n  xor rcx, r10\n  or r10, rax\n  sub r10, rcx\n",
        # (a + b) - (a | b), forming the OR term first (commuted from the base form).
        "  mov rcx, rax\n  or rcx, r10\n  add r10, rax\n  sub r10, rcx\n",
        # (a | ~b) & b: the second operand masked by the first-or-not-second.
        "  mov rcx, rax\n  not rcx\n  or rcx, r10\n  mov r10, rax\n  and r10, rcx\n",
        # (~b | a) & b: b masked by (a-or-not-b), the operands swapped from above.
        "  mov rcx, rax\n  not rcx\n  or rcx, r10\n  and r10, rax\n",
    ),
    "or": (
        # a + (~a & b): a plus the bits of b it does not already carry.
        "  mov rcx, r10\n  not rcx\n  and rcx, rax\n  add r10, rcx\n",
        # (a & ~b) | b, the disjoint-a term or'd (not added) with b.
        "  mov rcx, rax\n  not rcx\n  and r10, rcx\n  or r10, rax\n",
        # b + (a & ~b): the disjoint-a term added onto b instead of onto a.
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  mov r10, rax\n  add r10, rcx\n",
        # (a & b) + (a ^ b), the AND and XOR halves summed (carry + no-carry bits).
        "  mov rcx, r10\n  xor rcx, rax\n  and r10, rax\n  add r10, rcx\n",
        # a ^ (~a & b): adding the bits of b absent from a completes the OR (disjoint).
        "  mov rcx, r10\n  not rcx\n  and rcx, rax\n  xor r10, rcx\n",
        # (a & b) | (a ^ b), the AND and XOR halves or'd (commuted from the base form).
        "  mov rcx, rax\n  and rcx, r10\n  xor r10, rax\n  or r10, rcx\n",
        # b | (a & ~b): the bits of a absent from b, or'd onto b.
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  mov r10, rax\n  or r10, rcx\n",
    ),
}

_ADD_POOL: tuple[str, ...] = _MBA_ADD_TEMPLATES + _EXTRA_ADD_TEMPLATES
_BOOL_POOL: dict[str, tuple[str, ...]] = {
    mnemonic: _BOOL_VARIANTS[mnemonic] + _EXTRA_BOOL_VARIANTS[mnemonic] for mnemonic in _EXTRA_BOOL_VARIANTS
}

# Bits of ``arith_variant`` each mnemonic group reads (4 bits -> up to 16 pool
# entries, enough to reach every extended template). add/sub read [0:4), then
# xor/and/or index their own pools from the next three nibbles.
_BOOL_SHIFT: dict[str, int] = {"xor": 4, "and": 8, "or": 12}
ARITH_VARIANT_BITS = 16
_GROUP_MASK = 0xF


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


# Bits of ``addr_variant`` that pick the address-fold template. 4 bits reach every
# entry of the widened add pool (shared + region-local extras); 3 would leave the
# last extras unreachable.
ADDR_VARIANT_BITS = 4


def addr_fold(addend: str, temp: str, key: int, variant: int) -> str:
    """Compute ``r10 += addend`` for this build's address-fold personality.

    The memory-address prologues accumulate a base/index/displacement into r10 with
    an MBA add (never a literal ``add``). ``variant`` 0 returns the canonical,
    key-selected fold verbatim (byte-identical to :func:`_mba_add`); a non-zero
    ``variant`` selects over the shared add pool independently of ``key``, so two
    builds fold addresses with different algebra. Every pool template clobbers only
    r10 and ``temp`` and preserves ``addend`` - the exact register footprint of
    :func:`_mba_add` - so an address prologue's live-register contract is unchanged
    whichever variant is chosen.
    """
    if not variant:
        return _mba_add(addend, temp, key)
    return _ADD_POOL[variant % len(_ADD_POOL)].format(a=addend, t=temp)
