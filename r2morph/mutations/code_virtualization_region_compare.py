"""Per-build compare-realization spellings for the region VM.

``cmp``/``test`` set flags a later branch reads; the handlers compute the
comparison (``a - b`` / ``a & b``) into ``r10`` and then synthesize the flags by
hand (see :mod:`code_virtualization_region_flags`). The comparison value can be
spelled many algebraically-equivalent ways, so this module gives each build a
distinct spelling chosen by ``compare_variant`` - a different machine, not a
relabelled one - composing with the arithmetic fold (``arith_variant``) and the
flag synthesis (``flag_variant``).

The canonical spelling (``compare_variant`` 0) stays inline in the handlers, so a
build with ``isa_seed`` 0 is byte-identical to the pre-feature output; this module
is consulted only for the non-canonical builds. Every spelling obeys one contract:

    on entry  rbx = a, rbp = b, rax = b
    on exit   r10 = (a - b) for cmp / (a & b) for test; rbx, rbp preserved

so the flag synthesis (which reads a=rbx, b=rbp, result=r10, and preserves r8)
stays correct. Only rax/rcx/r10 are clobbered (``arith_fold`` itself touches only
rcx), never r8 or the operand registers. A 32-bit compare is truncated by the
handler's ``mov r10d, r10d`` after this returns, so the wide intermediates the
complement forms produce in the high half are discarded.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_fold import arith_fold

# Non-canonical spellings per op (index 0 is a self-contained canonical form used
# by non-zero builds whose derived choice lands on 0; the handlers keep their own
# inline canonical form for the byte-identical isa_seed 0 path).
_CMP_CHOICES = 3
_TEST_CHOICES = 2

# Width of the per-build selector. build_isa_spec draws randrange(1 << bits); the
# two op choices are derived independently from it, so 4 bits spread both evenly.
COMPARE_VARIANT_BITS = 4
_INVERTED_COMPUTE_VARIANT = 2


def _cmp_compute(key: int, arith_variant: int, choice: int) -> str:
    """``r10 = a - b`` from rbx=a, rbp=b, rax=b in one of several equivalent forms."""
    if choice == 1:
        # a - b == a + ~b + 1 (two's complement, +1 folded as a flag-neutral lea).
        return "  mov r10, rbx\n  not rax\n" + arith_fold("add", key, arith_variant) + "  lea r10, [r10 + 1]\n"
    if choice == _INVERTED_COMPUTE_VARIANT:
        # a - b == ~(~a + b).
        return "  mov r10, rbx\n  not r10\n" + arith_fold("add", key, arith_variant) + "  not r10\n"
    # choice 0: a + (-b).
    return "  mov r10, rbx\n  neg rax\n" + arith_fold("add", key, arith_variant)


def _test_compute(key: int, arith_variant: int, choice: int) -> str:
    """``r10 = a & b`` from rbx=a, rbp=b, rax=b in one of several equivalent forms."""
    if choice == 1:
        # a & b == ~(~a | ~b) (De Morgan), the inner OR via the MBA fold.
        return "  mov r10, rbx\n  not r10\n  not rax\n" + arith_fold("or", key, arith_variant) + "  not r10\n"
    # choice 0: a & b directly via the MBA fold.
    return "  mov r10, rbx\n" + arith_fold("and", key, arith_variant)


def compare_compute(mnemonic: str, key: int, arith_variant: int, compare_variant: int) -> str:
    """The non-canonical compare value computation for this build (mnemonic cmp/test).

    Only called for ``compare_variant != 0``; the two op choices are derived
    independently so cmp and test diverge per build without being coupled.
    """
    if mnemonic == "cmp":
        return _cmp_compute(key, arith_variant, compare_variant % _CMP_CHOICES)
    return _test_compute(key, arith_variant, (compare_variant // _CMP_CHOICES) % _TEST_CHOICES)
