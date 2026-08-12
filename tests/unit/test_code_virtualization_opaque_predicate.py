"""
Unit tests for the opaque-predicate branch injected at VM handler heads.

Each predicate computes a value whose parity is fixed for every input (e.g.
``x*(x+1)`` is always even, ``x|1`` is always odd), paired with the branch that
is consequently always taken, so the junk body between the branch and the skip
label is unreachable. These tests pin the form, prove the per-instance form is
varied, and - by assembling each variant and emulating it for a spread of seed
values - prove the branch is taken regardless of input. That is the soundness
both VMs rely on when they place the predicate over state-neutral scratch at a
handler head.
"""

from __future__ import annotations

import random

import pytest

from r2morph.mutations.code_virtualization_engine import _OPAQUE_VARIANTS as _ENGINE_VARIANTS
from r2morph.mutations.code_virtualization_engine import _opaque_predicate_asm as _engine_opaque
from r2morph.mutations.code_virtualization_region_control_handlers import _OPAQUE_VARIANTS as _REGION_VARIANTS
from r2morph.mutations.code_virtualization_region_control_handlers import _opaque_predicate_asm as _region_opaque

# Both VMs carry their own parallel junk machinery; the opaque predicate is the
# same technique in each, so every test runs against both builders.
_BUILDERS = (_region_opaque, _engine_opaque)

# Spread of seed values covering even, odd, zero, all-ones, and high-bit set, so
# overflow past 64 bits is exercised - the low bit (parity) is what every guard
# tests, and it stays correct under wraparound.
_SEEDS = (0, 1, 2, 3, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000, 0xDEADBEEFCAFEB0BA, 0x7FFFFFFFFFFFFFFF)


@pytest.mark.parametrize("builder", _BUILDERS)
def test_opaque_predicate_has_the_parity_guard_shape(builder) -> None:
    asm = builder(random.Random(1), 7)
    assert "test rbp, 1\n" in asm  # every variant tests the low bit of rbp
    assert " opaque_7\n" in asm  # the always-taken branch targets the skip label
    assert asm.rstrip().endswith("opaque_7:")


@pytest.mark.parametrize("builder", _BUILDERS)
def test_opaque_predicate_label_tracks_the_index(builder) -> None:
    # The skip label must be keyed on the handler index so it stays unique across
    # handler instances and nested layers.
    assert " opaque_42\n" in builder(random.Random(1), 42)
    assert builder(random.Random(1), 42).rstrip().endswith("opaque_42:")


@pytest.mark.parametrize("builder", _BUILDERS)
def test_opaque_predicate_form_is_polymorphic_across_instances(builder) -> None:
    # A fixed predicate is itself a signature; over many instances every variant
    # form must be reachable so the predicate is not one recognizable pattern.
    forms = {builder(random.Random(seed), 0).split(" opaque_0\n", 1)[0] for seed in range(400)}
    # Four seed registers x five identities = twenty distinct head forms.
    assert len(forms) == 4 * len(_REGION_VARIANTS)


def test_both_vms_share_the_same_variant_set() -> None:
    assert _REGION_VARIANTS == _ENGINE_VARIANTS


@pytest.mark.parametrize("variant", range(len(_REGION_VARIANTS)))
@pytest.mark.parametrize("seed_value", _SEEDS)
@pytest.mark.parametrize("seed_reg", ("rbx", "r12", "rsi", "r13"))
def test_opaque_predicate_branch_is_always_taken(variant: int, seed_value: int, seed_reg: str) -> None:
    # Assemble each variant followed by a sentinel store in the (supposedly
    # unreachable) dead body, and emulate it. The sentinel (r14, untouched by the
    # predicate) must never be written, proving the branch is always taken for
    # every variant, every input, and every seed register - including the live
    # rsi/r13 the real VM keeps.
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_RBX, UC_X86_REG_RSI

    compute, branch = _REGION_VARIANTS[variant]
    asm = f"{compute.format(s=seed_reg)}  {branch} opaque_0\n  mov r14, 1\nopaque_0:\n"

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    for reg in (UC_X86_REG_RBX, UC_X86_REG_R12, UC_X86_REG_RSI, UC_X86_REG_R13):
        mu.reg_write(reg, seed_value)
    mu.reg_write(UC_X86_REG_R14, 0)
    mu.emu_start(0x1000, 0x1000 + len(code))
    # r14 stays 0 only if the dead `mov r14, 1` was skipped.
    assert mu.reg_read(UC_X86_REG_R14) == 0
