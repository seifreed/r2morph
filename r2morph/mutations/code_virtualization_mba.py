"""
Mixed boolean-arithmetic (MBA) rewrites shared by both virtualization VMs.

A handler that contains a literal ``add``/``sub``/``xor``/``and``/``or`` is a
gift to a devirtualizer: the native mnemonic names the operation. These builders
emit algebraically-equivalent MBA sequences instead, so the handler never spells
out the operation it performs, and several identities are kept per operation so
the rewrite is not a single fixed signature across samples.

The builders are pure ``(key) -> asm string`` functions with no dependencies, so
both the straight-line engine (:mod:`code_virtualization_engine`) and the region
handlers (:mod:`code_virtualization_region_handlers`) import them without a layer
cycle. All sequences operate on ``r10`` (the accumulator ``a``) and ``rax`` (the
operand ``b``) and clobber only ``rcx`` as scratch; callers use them where the
flags they set are dead.
"""

from __future__ import annotations

# Each template computes ``r10 += {a}`` (a == r10, b == {a}) and preserves the
# addend ``{a}``, clobbering only r10 and the temp ``{t}``. lea is flag-neutral;
# the xor/and/or/sub/add/neg/not/shl set flags — harmless wherever these run in a
# flag-dead context. The identities deliberately span different shapes (half-adder
# via lea, two's-complement folds via not/neg, an explicit shl carry) so the fold
# is not one fixed signature across samples. ``{t}`` is a free temp, ``{a}`` the addend.
_MBA_ADD_TEMPLATES: tuple[str, ...] = (
    # a + b == (a ^ b) + 2*(a & b)
    "  mov {t}, r10\n  xor {t}, {a}\n  and r10, {a}\n  lea r10, [{t} + r10*2]\n",
    # a + b == (a | b) + (a & b)
    "  mov {t}, r10\n  and {t}, {a}\n  or r10, {a}\n  lea r10, [r10 + {t}]\n",
    # a + b == 2*(a | b) - (a ^ b)
    "  mov {t}, r10\n  xor {t}, {a}\n  or r10, {a}\n  lea r10, [r10*2]\n  sub r10, {t}\n",
    # a + b == -(~a + ~b) - 2
    "  mov {t}, {a}\n  not {t}\n  not r10\n  add r10, {t}\n  neg r10\n  sub r10, 2\n",
    # a + b == a - ~b - 1
    "  mov {t}, {a}\n  not {t}\n  sub r10, {t}\n  sub r10, 1\n",
    # a + b == (a ^ b) + ((a & b) << 1)
    "  mov {t}, r10\n  and {t}, {a}\n  shl {t}, 1\n  xor r10, {a}\n  add r10, {t}\n",
)


def _mba_add(addend: str, temp: str, key: int) -> str:
    """A per-instance MBA rewrite of ``r10 += addend`` (chosen by the bytecode key)."""
    return _MBA_ADD_TEMPLATES[key % len(_MBA_ADD_TEMPLATES)].format(a=addend, t=temp)


def _mba_add_r10_rax(key: int) -> str:
    """The MBA rewrite of ``r10 += rax`` used to fold a displacement."""
    return _mba_add("rax", "rcx", key)


# Each boolean op carries several equivalent per-instance rewrites so a handler is
# neither the plain op nor a single fixed MBA signature across samples. Each pool
# mixes pure-boolean De Morgan identities with arithmetic-blended ones (add/sub of
# the AND/OR/XOR half-adder terms), genuinely different micro-op sequences that an
# MBA simplifier keyed on a single boolean shape does not match. All operate on r10
# (a) and rax (b), preserve rax, and clobber only rcx as scratch; they run only
# where flags are dead. Compute r10 = r10 <op> rax.
_BOOL_VARIANTS: dict[str, tuple[str, ...]] = {
    "xor": (
        # (a | b) & ~(a & b)
        "  mov rcx, r10\n  and rcx, rax\n  or r10, rax\n  not rcx\n  and r10, rcx\n",
        # (a & ~b) | (~a & b)
        "  mov rcx, rax\n  not rcx\n  and rcx, r10\n  not r10\n  and r10, rax\n  or r10, rcx\n",
        # (a | b) - (a & b)
        "  mov rcx, r10\n  and rcx, rax\n  or r10, rax\n  sub r10, rcx\n",
        # (a + b) - 2*(a & b)
        "  mov rcx, r10\n  and rcx, rax\n  add r10, rax\n  sub r10, rcx\n  sub r10, rcx\n",
        # (a | b) + ~(a & b) + 1
        "  mov rcx, r10\n  and rcx, rax\n  not rcx\n  or r10, rax\n  add r10, rcx\n  add r10, 1\n",
    ),
    "and": (
        # ~(~a | ~b)
        "  not r10\n  mov rcx, rax\n  not rcx\n  or r10, rcx\n  not r10\n",
        # (a ^ b) ^ (a | b)
        "  mov rcx, r10\n  or rcx, rax\n  xor r10, rax\n  xor r10, rcx\n",
        # (a | b) - (a ^ b)
        "  mov rcx, r10\n  xor rcx, rax\n  or r10, rax\n  sub r10, rcx\n",
        # (a + b) - (a | b)
        "  mov rcx, r10\n  or rcx, rax\n  add r10, rax\n  sub r10, rcx\n",
        # b - (~a & b)
        "  mov rcx, r10\n  not rcx\n  and rcx, rax\n  mov r10, rax\n  sub r10, rcx\n",
    ),
    "or": (
        # ~(~a & ~b)
        "  not r10\n  mov rcx, rax\n  not rcx\n  and r10, rcx\n  not r10\n",
        # (a ^ b) | (a & b)
        "  mov rcx, r10\n  and rcx, rax\n  xor r10, rax\n  or r10, rcx\n",
        # (a ^ b) + (a & b)
        "  mov rcx, r10\n  and rcx, rax\n  xor r10, rax\n  add r10, rcx\n",
        # (a + b) - (a & b)
        "  mov rcx, r10\n  and rcx, rax\n  add r10, rax\n  sub r10, rcx\n",
        # (a & ~b) + b
        "  mov rcx, rax\n  not rcx\n  and r10, rcx\n  add r10, rax\n",
    ),
}


def _op_mba_compute(mnemonic: str, key: int) -> str:
    """Compute ``r10 = r10 <op> rax`` with no literal native op (r10 == a, rax == b).

    add/sub use the polymorphic MBA add fold (sub must already have negated its
    source); the boolean ops select one of several per-instance MBA rewrites (a key
    field picks the variant), so the handler never contains the plain xor/and/or it
    stands for and the rewrite is not a single fixed signature. ``not``/``lea`` are
    flag-neutral and the boolean ops set only dead flags. rcx is the free scratch.
    """
    if mnemonic in ("add", "sub"):
        return _mba_add("rax", "rcx", key)
    variants = _BOOL_VARIANTS[mnemonic]
    return variants[(key >> 4) % len(variants)]
