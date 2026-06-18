"""
Unit tests for the mixed-boolean-arithmetic (MBA) address computation.

The shared address prologues fold both the base and the displacement with one of
several equivalent MBA identities (chosen per instance) instead of a literal
``add``, so the handler's address arithmetic is neither a plain pattern nor a
single fixed MBA signature. Semantics are covered by the memory fixtures; these
tests pin the obfuscation form and its polymorphism on the real builders.
"""

from __future__ import annotations

import pytest

from r2morph.mutations.code_virtualization_mba import (
    _MBA_ADD_TEMPLATES,
    _mba_add,
    _mba_add_r10_rax,
    _op_mba_compute,
)
from r2morph.mutations.code_virtualization_region_handlers import (
    _indexed_address_asm,
    _mem_address_asm,
)

_MASK64 = (1 << 64) - 1
_BOOLEAN_OPS = (
    ("xor", lambda a, b: a ^ b),
    ("and", lambda a, b: a & b),
    ("or", lambda a, b: a | b),
)
# Bytecode keys whose (key >> 4) % 3 is 0, 1, 2 — selecting each boolean MBA variant.
_VARIANT_KEYS = (0x01, 0x10, 0x20)
_SAMPLES = (
    (0xCAFEB0BA12345678, 0x0F0F0F0FF0F0F0F0),
    (0xFFFFFFFFFFFFFFFF, 0x0000000000000000),
    (0xDEADBEEF00000000, 0x00000000DEADBEEF),
    (0x123456789ABCDEF0, 0xFEDCBA9876543210),
)


def test_no_address_prologue_uses_a_literal_add() -> None:
    for key in range(1, 256):
        for asm in (
            _mem_address_asm(False, key, "0x6c6c6c6c")[0],
            _mem_address_asm(True, key, "0x6c6c6c6c")[0],
            _indexed_address_asm(key, "0x6c6c6c6c")[0],
        ):
            assert "add r10, rax" not in asm
            assert "add r10, qword ptr [rsp+r9*8]" not in asm


def test_displacement_fold_is_one_of_the_known_mba_variants() -> None:
    for key in range(1, 256):
        assert _mba_add_r10_rax(key) == _mba_add("rax", "rcx", key)
        assert _mba_add("rax", "rcx", key) in {t.format(a="rax", t="rcx") for t in _MBA_ADD_TEMPLATES}


def test_mba_variant_is_polymorphic_across_instances() -> None:
    # Different bytecode keys must be able to select different folds, so the MBA
    # is not a single fixed pattern across samples.
    produced = {_mba_add_r10_rax(key) for key in range(1, 256)}
    assert len(produced) == len(_MBA_ADD_TEMPLATES) > 1


def test_boolean_mba_never_contains_the_literal_native_op() -> None:
    # The handler for op X must not contain the plain `X r10, rax` it stands for.
    # Match the whole indented instruction so `or` does not falsely hit `xor`.
    for mnemonic, _ in _BOOLEAN_OPS:
        for key in range(1, 256):
            assert f"  {mnemonic} r10, rax\n" not in _op_mba_compute(mnemonic, key)


def test_boolean_mba_is_polymorphic_across_instances() -> None:
    # Three equivalent rewrites per op (two pure-boolean, one arithmetic-mixed).
    for mnemonic, _ in _BOOLEAN_OPS:
        assert len({_op_mba_compute(mnemonic, key) for key in range(1, 256)}) == 3


@pytest.mark.parametrize("mnemonic,native", _BOOLEAN_OPS)
@pytest.mark.parametrize("key", _VARIANT_KEYS)
def test_boolean_mba_computes_the_native_operation(mnemonic: str, native, key: int) -> None:
    # Emulate `r10 = r10 <op> rax` for both per-instance MBA variants and verify it
    # equals the native boolean operation for every sample (a == r10, b == rax).
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_R10, UC_X86_REG_RAX

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    for a, b in _SAMPLES:
        asm = f"mov r10, {hex(a)}\n  mov rax, {hex(b)}\n" + _op_mba_compute(mnemonic, key)
        code, _ = ks.asm(asm, 0x1000)
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        mu.mem_map(0x1000, 0x1000)
        mu.mem_write(0x1000, bytes(code))
        mu.reg_write(UC_X86_REG_RAX, b)
        mu.reg_write(UC_X86_REG_R10, a)
        mu.emu_start(0x1000, 0x1000 + len(code))
        assert mu.reg_read(UC_X86_REG_R10) == native(a, b) & _MASK64
