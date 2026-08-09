"""
Per-build flag-synthesis personality for the region VM (semantic ISA axis).

Every flag-setting region handler synthesizes the readable RFLAGS of its
operation by hand - no literal flag-setting native op, no ``pushfq`` - so a
devirtualizer never sees the operation named. Until now that synthesis had a
single fixed spelling shared by every build: two samples computed CF/OF/SF/ZF/PF
with byte-identical assembly, a stable cross-sample signature.

This module forks that synthesis into equivalent per-build spellings. Each of the
five synthesized flags (ZF, SF, CF, OF, PF) has a canonical spelling and one
algebraically-equivalent alternate; a build's ``flag_variant`` is a small bit
vector (bit i selects flag i's spelling), so 32 distinct-but-equivalent
flag-synthesis machines exist and :mod:`code_virtualization_region_isa` picks one
per build from the isa_seed. ``flag_variant`` 0 is the canonical spelling
(byte-identical to the pre-feature output), so existing seeds are unchanged.

The register contract is fixed for every spelling: ``a`` is read from rbx/ebx,
``b`` from rbp/ebp, the result from r10/r10d; the RFLAGS image is built in r11;
rcx/rax/r9 (and their 32-bit spellings) are scratch; r8 is preserved. Every
spelling is verified bit-for-bit against the CPU over operand edge cases in
``tests/unit/test_code_virtualization_isa_flags.py``.
"""

from __future__ import annotations

# Number of independently-selected flag spellings (ZF, SF, CF, OF, PF), i.e. the
# width in bits of ``flag_variant``. 32 personalities from two spellings each.
FLAG_VARIANT_BITS = 5


def _regs(width: int) -> tuple[str, str, str, str, str, str]:
    """(a, b, result, scratch c, scratch t, scratch u) register spellings."""
    if width == 64:
        return "rbx", "rbp", "r10", "rcx", "rax", "r9"
    return "ebx", "ebp", "r10d", "ecx", "eax", "r9d"


def _zf(width: int, spelling: int) -> str:
    _a, _b, r, c, t, _u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return (
            f"  mov {c}, {r}\n  neg {c}\n  or {c}, {r}\n  shr {c}, {sh}\n"
            f"  and {c}, 1\n  xor {c}, 1\n  shl {c}, 6\n  or r11, rcx\n"
        )
    # Alternate: smear any set bit of the result down to bit 0 (bit 0 == 1 iff the
    # result is nonzero), then invert for ZF.
    lines = [f"  mov {c}, {r}\n"]
    shift = 1
    while shift < width:
        lines.append(f"  mov {t}, {c}\n  shr {t}, {shift}\n  or {c}, {t}\n")
        shift *= 2
    lines.append(f"  and {c}, 1\n  xor {c}, 1\n  shl {c}, 6\n  or r11, rcx\n")
    return "".join(lines)


def _sf(width: int, spelling: int) -> str:
    _a, _b, r, c, t, _u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return f"  mov {c}, {r}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 7\n  or r11, rcx\n"
    # Alternate: isolate the sign bit with a mask, then shift it to bit 7.
    if width == 64:
        return f"  mov {c}, {r}\n  mov {t}, 0x8000000000000000\n  and {c}, {t}\n  shr {c}, 56\n  or r11, rcx\n"
    if width == 8:
        # The 8-bit sign bit (bit 7) is already the SF position (bit 7): mask it, no shift.
        return f"  mov {c}, {r}\n  and {c}, 0x80\n  or r11, rcx\n"
    return f"  mov {c}, {r}\n  and {c}, 0x80000000\n  shr {c}, 24\n  or r11, rcx\n"


def _cf_add(width: int, spelling: int) -> str:
    a, b, r, c, t, u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return (
            f"  mov {c}, {a}\n  and {c}, {b}\n  mov {u}, {a}\n  or {u}, {b}\n  mov {t}, {r}\n"
            f"  not {t}\n  and {u}, {t}\n  or {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
    # Alternate: the carry-out is the majority of a, b and ~result.
    return (
        f"  mov {t}, {r}\n  not {t}\n  mov {c}, {a}\n  and {c}, {b}\n"
        f"  mov {u}, {a}\n  and {u}, {t}\n  or {c}, {u}\n"
        f"  mov {u}, {b}\n  and {u}, {t}\n  or {c}, {u}\n"
        f"  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
    )


def _of_add(width: int, spelling: int) -> str:
    a, b, r, c, t, u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return (
            f"  mov {c}, {a}\n  xor {c}, {r}\n  mov {u}, {b}\n  xor {u}, {r}\n"
            f"  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    # Alternate: overflow iff the operands share a sign and the result differs.
    return (
        f"  mov {c}, {a}\n  xor {c}, {b}\n  not {c}\n  mov {t}, {a}\n  xor {t}, {r}\n"
        f"  and {c}, {t}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
    )


def _cf_sub(width: int, spelling: int) -> str:
    a, b, r, c, t, u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return (
            f"  mov {c}, {a}\n  not {c}\n  and {c}, {b}\n  mov {u}, {a}\n  not {u}\n  or {u}, {b}\n"
            f"  and {u}, {r}\n  or {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
    # Alternate: the borrow-out is the majority of ~a, b and the result.
    return (
        f"  mov {t}, {a}\n  not {t}\n  mov {c}, {t}\n  and {c}, {b}\n"
        f"  mov {u}, {t}\n  and {u}, {r}\n  or {c}, {u}\n"
        f"  mov {u}, {b}\n  and {u}, {r}\n  or {c}, {u}\n"
        f"  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
    )


def _of_sub(width: int, spelling: int) -> str:
    a, b, r, c, t, u = _regs(width)
    sh = width - 1
    if spelling == 0:
        return (
            f"  mov {c}, {a}\n  xor {c}, {b}\n  mov {u}, {a}\n  xor {u}, {r}\n"
            f"  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    # Alternate: overflow iff the operands differ in sign and the result shares
    # the subtrahend's sign.
    return (
        f"  mov {c}, {a}\n  xor {c}, {b}\n  mov {t}, {b}\n  xor {t}, {r}\n  not {t}\n"
        f"  and {c}, {t}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
    )


def _pf(width: int, spelling: int) -> str:
    _a, _b, _r, c, t, u = _regs(width)
    if spelling == 0:
        return (
            f"  movzx ecx, r10b\n  mov {u}, {c}\n  shr {u}, 4\n  xor {c}, {u}\n"
            f"  mov {u}, {c}\n  shr {u}, 2\n  xor {c}, {u}\n  mov {u}, {c}\n  shr {u}, 1\n"
            f"  xor {c}, {u}\n  not {c}\n  and ecx, 1\n  shl ecx, 2\n  or r11, rcx\n"
        )
    # Alternate: fold the low byte to a nibble, then index a 16-entry parity table
    # (bit n of 0x9669 is 1 iff nibble n has even parity).
    return (
        "  movzx ecx, r10b\n  mov eax, ecx\n  shr eax, 4\n  xor ecx, eax\n  and ecx, 0xF\n"
        "  mov eax, 0x9669\n  shr eax, cl\n  and eax, 1\n  shl eax, 2\n  or r11, rax\n"
    )


def synth_flags_asm(width: int, mode: str, variant: int = 0) -> str:
    """Branchlessly synthesize the readable flags of ``a <op> b`` into r11.

    Reads ``a`` in rbx, ``b`` in rbp and the result in r10 (32-bit spellings for
    ``width`` 32 and 8); builds the RFLAGS image in r11; rcx/rax/r9 are scratch and
    r8 is preserved. ``width`` 8 reuses the 32-bit register spellings but keys the
    sign bit off ``width - 1`` (7); the caller must mask ``a``/``b``/result to the
    low byte first so the upper bytes of the context slots do not perturb the sign,
    carry or overflow. ``mode`` is ``"add"``, ``"sub"`` or ``"logic"`` (and/or/xor/test).
    SF, ZF and PF are always set; add/sub additionally set CF and OF (logic clears
    both, so nothing is emitted for them). AF is read by no conditional jump and is
    omitted. ``variant`` selects, per flag, one of two algebraically-equivalent
    spellings (bit 0 ZF, 1 SF, 2 CF, 3 OF, 4 PF); ``variant`` 0 is the canonical
    spelling, byte-identical to the pre-feature output.
    """
    lines = ["  xor r11d, r11d\n"]
    lines.append(_zf(width, variant & 1))
    lines.append(_sf(width, (variant >> 1) & 1))
    if mode == "add":
        lines.append(_cf_add(width, (variant >> 2) & 1))
        lines.append(_of_add(width, (variant >> 3) & 1))
    elif mode == "sub":
        lines.append(_cf_sub(width, (variant >> 2) & 1))
        lines.append(_of_sub(width, (variant >> 3) & 1))
    lines.append(_pf(width, (variant >> 4) & 1))
    return "".join(lines)
