"""Value-equivalence for the per-build address-fold ISA personality.

The memory-address prologues accumulate ``r10 += addend`` with an MBA rewrite
selected per build by ``addr_variant``. Every variant must compute the same 64-bit
address as a literal add and must clobber only r10 and the temp (preserving the
addend), so the prologue's register contract is unchanged. These tests assemble
each variant and run it under Unicorn, comparing r10 against ``a + b`` and checking
the addend register survives; variant 0 is asserted byte-identical to ``_mba_add``.
"""

from __future__ import annotations

from contextlib import suppress

import keystone
import unicorn
from unicorn import x86_const

from r2morph.mutations.code_virtualization_fold import ADDR_VARIANT_BITS, addr_fold
from r2morph.mutations.code_virtualization_mba import _mba_add

_MASK64 = (1 << 64) - 1
_CODE = 0x400000
# (addend register, temp register) pairs the real address prologues use.
_REG_PAIRS = (("rax", "rcx"), ("r11", "rcx"))
_OPERANDS = (
    0,
    1,
    2,
    (1 << 64) - 1,
    (1 << 63),
    (1 << 63) - 1,
    0xDEADBEEF,
    0x1000,
    0xFFFFFFFF,
    0x0123456789ABCDEF,
)
_ADDEND_REG = {"rax": x86_const.UC_X86_REG_RAX, "r11": x86_const.UC_X86_REG_R11}


def _run(asm: str, a: int, b: int, addend: str) -> tuple[int, int]:
    """Assemble ``asm`` with r10=a and the addend register=b, run it, return
    (r10, addend-register) after execution."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm + "  hlt\n", addr=_CODE, as_bytes=True)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(_CODE, 0x1000)
    uc.mem_write(_CODE, code)
    uc.reg_write(x86_const.UC_X86_REG_R10, a)
    uc.reg_write(_ADDEND_REG[addend], b)
    with suppress(unicorn.UcError):
        uc.emu_start(_CODE, _CODE + len(code))
    return uc.reg_read(x86_const.UC_X86_REG_R10), uc.reg_read(_ADDEND_REG[addend])


def test_addr_fold_variants_compute_the_sum_over_edge_operands() -> None:
    for variant in range(1, 1 << ADDR_VARIANT_BITS):
        for addend, temp in _REG_PAIRS:
            asm = addr_fold(addend, temp, key=0x5A, variant=variant)
            for a in _OPERANDS:
                for b in _OPERANDS:
                    r10, kept = _run(asm, a, b, addend)
                    assert r10 == ((a + b) & _MASK64), (variant, addend, hex(a), hex(b))
                    assert kept == (b & _MASK64), f"variant {variant} clobbered the addend {addend}"


def test_addr_fold_variant_zero_is_byte_identical_to_mba_add() -> None:
    for addend, temp in _REG_PAIRS:
        for key in (0, 1, 0x5A, 0xFF):
            assert addr_fold(addend, temp, key, 0) == _mba_add(addend, temp, key)


def test_addr_fold_variants_diverge() -> None:
    seen = {addr_fold("rax", "rcx", key=0x5A, variant=v) for v in range(1, 1 << ADDR_VARIANT_BITS)}
    assert len(seen) > 1, "address folds do not diverge across variants"
