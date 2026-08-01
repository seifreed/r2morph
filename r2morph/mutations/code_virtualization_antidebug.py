"""Timing anti-debug folded into the VM's runtime self-checksum.

The interpreter already rolls a one-byte checksum of its own body into a frame
slot and folds that slot into every opcode and table-entry decrypt, so a tampered
interpreter misdecodes and the dispatch bounds-guard routes control to the early
exit - there is no comparison or conditional branch to patch out. This module
reuses that exact slot: it times a short instruction window with the timestamp
counter and folds a *branch-free* 0-or-0xFF byte into the same slot.

An untraced run - and a Unicorn emulation - observes a tiny inter-read delta
(``< 2**N`` cycles), so the folded byte is provably ``0x00`` for EVERY per-build
variant. The stored checksum then stays exactly ``compute_build_checksum(...)``,
the encoder's opcode bias cancels as before, and the decode is bit-identical to a
build without the fold. A single-stepping debugger inflates the delta past
``2**N`` (a per-instruction ptrace trap dwarfs a handful of native cycles), the
byte becomes ``0xFF``, and every subsequent opcode and table entry misdecodes into
the exit path.

Because the benign contribution is ``0`` for all variants, the polymorphism below
has no Python mirror to keep in sync and cannot desync the checksum. The emitted
counter reads sit inside ``[vm_entry, vm_table/vm_code_end)`` - the range
``compute_build_checksum`` already covers - so neither the encoder nor the
checksum computation changes.

The fold runs right after the checksum prologue and before dispatch, where every
GP register is already spilled to the frame; it touches only ``rax``/``rdx``/
``rcx``/``r8`` (all spilled, and ``rax`` is overwritten by the next prologue line),
never the not-yet-loaded ``rsi``/``r13``/``r14``/``r15``.
"""

from __future__ import annotations

import random

# A benign inter-read delta is a few hundred native cycles, far under ``2**16``;
# a single-step trap (a kernel round-trip per instruction) inflates it past any of
# these. 16-18 keeps the untraced path inert while still catching tracing.
_SHIFT_CHOICES = (16, 17, 18)

# Branch-free reductions of "delta is non-zero" to ``al`` in ``{0x00, 0xFF}``.
# After ``neg rax`` the carry flag is set iff ``rax`` was non-zero, so ``sbb X, X``
# yields ``-CF`` (0 or all-ones) and ``al`` carries the same low byte in any width.
_REDUCE_CHOICES = ("sbb eax, eax", "sbb rax, rax", "sbb al, al")

# The counter read leaves the timestamp in ``edx:eax`` (both zero-extended); the
# high half is disjoint from the low half, so ``or`` and ``add`` assemble the same
# 64-bit value.
_COMBINE_CHOICES = ("or", "add")

# Register pool for the surviving first timestamp and the discardable work window.
# ``r8`` always survives the second read; ``rcx`` survives only under plain
# ``rdtsc`` (``rdtscp`` writes ``ecx`` with TSC_AUX).
_SCRATCH_HIGH = "r8"
_SCRATCH_LOW = "rcx"

# Maximum window increment: keeps the work-window constant a small immediate.
_WINDOW_MASK = 0x7F


def _dword_name(reg64: str) -> str:
    """The 32-bit sub-register spelling for the scratch 64-bit registers used here."""
    return {"r8": "r8d", "rcx": "ecx"}[reg64]


def _combine_timestamp(combine: str) -> str:
    """Assemble the counter's ``edx:eax`` pair into a 64-bit value in ``rax``."""
    return f"  shl rdx, 32\n  {combine} rax, rdx\n"


def _work_window(work_reg: str, key: int) -> str:
    """State-neutral cycles between the two reads on a discardable scratch register.

    The result is never read; the window exists only so a debugger's per-instruction
    single-step overhead has something to accumulate against the timestamp delta.
    """
    reg = _dword_name(work_reg)
    step = (key & _WINDOW_MASK) + 1
    return f"  xor {reg}, {reg}\n  add {reg}, {step}\n  imul {reg}, {reg}, 3\n  rol {reg}, 1\n"


def timing_fold_asm(key: int, slot: int) -> str:
    """Assembly that folds a timing signal into the checksum ``slot`` byte.

    Emitted after ``checksum_prologue_asm`` and before dispatch. ``key`` (the
    build's ``xor_key``) selects the shift, the scratch registers, the fence
    bracketing, the read instruction and the reduce spelling; because the benign
    contribution is ``0`` for every choice, the variation is free of any Python
    mirror. ``slot`` is the frame offset of the checksum byte (engine and region
    interpreters use different offsets).
    """
    rng = random.Random(key)
    shift = rng.choice(_SHIFT_CHOICES)
    use_rdtscp = rng.random() < 0.5
    use_lfence = rng.random() < 0.5
    reduce_spelling = rng.choice(_REDUCE_CHOICES)
    combine = rng.choice(_COMBINE_CHOICES)

    read = "rdtscp" if use_rdtscp else "rdtsc"
    # The first timestamp must survive the second read. ``rdtscp`` clobbers ``rcx``,
    # so it can only live in ``r8`` there; plain ``rdtsc`` may keep it in either.
    first_reg = _SCRATCH_HIGH if use_rdtscp else rng.choice((_SCRATCH_HIGH, _SCRATCH_LOW))
    work_reg = _SCRATCH_LOW if first_reg == _SCRATCH_HIGH else _SCRATCH_HIGH

    fence = "  lfence\n" if use_lfence else ""
    return (
        f"  {read}\n"
        + _combine_timestamp(combine)
        + f"  mov {first_reg}, rax\n"
        + fence
        + _work_window(work_reg, key)
        + fence
        + f"  {read}\n"
        + _combine_timestamp(combine)
        + f"  sub rax, {first_reg}\n"
        + f"  shr rax, {shift}\n"
        + "  neg rax\n"
        + f"  {reduce_spelling}\n"
        + f"  xor byte ptr [rsp+{slot}], al\n"
    )
