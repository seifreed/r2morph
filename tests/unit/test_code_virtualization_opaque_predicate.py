"""
Unit tests for the opaque-predicate branch injected at region-VM handler heads.

The predicate ``x*(x+1)`` is even for every integer x, so the guard ``test rbp,
1`` always clears bit 0 and the ``jz`` is always taken: the junk body between the
branch and the skip label is unreachable. These tests pin the form and, by
assembling the snippet and emulating it for a spread of seed values, prove the
branch is taken regardless of input - the soundness the region VM relies on when
it places the predicate over state-neutral scratch at a handler head.
"""

from __future__ import annotations

import random

import pytest

from r2morph.mutations.code_virtualization_engine import _opaque_predicate_asm as _engine_opaque
from r2morph.mutations.code_virtualization_region_codegen import _opaque_predicate_asm as _region_opaque

# Both VMs carry their own parallel junk machinery; the opaque predicate is the
# same technique in each, so every test runs against both builders.
_BUILDERS = (_region_opaque, _engine_opaque)

_MASK64 = (1 << 64) - 1
# Spread of seed values covering even, odd, zero, all-ones, and high-bit set, so
# overflow of x*(x+1) past 64 bits is exercised - the low bit (parity) is what
# the guard tests, and it stays 0 under wraparound.
_SEEDS = (0, 1, 2, 3, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000, 0xDEADBEEFCAFEB0BA, 0x7FFFFFFFFFFFFFFF)


@pytest.mark.parametrize("builder", _BUILDERS)
def test_opaque_predicate_has_the_always_even_guard_shape(builder) -> None:
    asm = builder(random.Random(1), 7)
    assert "imul rbp," in asm
    assert "test rbp, 1\n" in asm
    assert "jz opaque_7\n" in asm
    assert asm.rstrip().endswith("opaque_7:")


@pytest.mark.parametrize("builder", _BUILDERS)
def test_opaque_predicate_label_tracks_the_index(builder) -> None:
    # The skip label must be keyed on the handler index so it stays unique across
    # handler instances and nested layers.
    assert "jz opaque_42\n" in builder(random.Random(1), 42)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("seed_value", _SEEDS)
def test_opaque_predicate_branch_is_always_taken(builder, seed_value: int) -> None:
    # Assemble the predicate followed by the real path, and place a sentinel store
    # in the (supposedly unreachable) dead body. Emulate from both possible scratch
    # values; the sentinel must never be written, proving the jz is always taken.
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_RBX

    # Force the dead body to a single observable store, independent of the rng's
    # junk choice, by rewriting whatever junk lines sit between the jz and label.
    raw = builder(random.Random(seed_value & 0xFF), 0)
    head, _, tail = raw.partition("\n  jz opaque_0\n")
    asm = f"{head}\n  jz opaque_0\n  mov r13, 1\nopaque_0:\n"

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    mu.reg_write(UC_X86_REG_RBX, seed_value)
    mu.reg_write(UC_X86_REG_R12, seed_value)
    mu.reg_write(UC_X86_REG_R13, 0)
    mu.emu_start(0x1000, 0x1000 + len(code))
    # r13 stays 0 only if the dead `mov r13, 1` was skipped.
    assert mu.reg_read(UC_X86_REG_R13) == 0
