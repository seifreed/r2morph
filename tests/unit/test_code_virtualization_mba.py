"""
Unit tests for the mixed-boolean-arithmetic (MBA) address computation.

The shared address prologues fold both the base and the displacement with one of
several equivalent MBA identities (chosen per instance) instead of a literal
``add``, so the handler's address arithmetic is neither a plain pattern nor a
single fixed MBA signature. These tests pin the obfuscation form and its
polymorphism, and prove — by assembling every template with keystone and
emulating it under unicorn — that each identity computes exactly the native
operation while honouring the register contract (add folds preserve the addend;
boolean rewrites preserve ``rax`` and clobber only ``rcx``).
"""

from __future__ import annotations

import importlib

import pytest

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_mba import (
    _BOOL_VARIANTS,
    _MBA_ADD_TEMPLATES,
    _mba_add,
    _mba_add_r10_rax,
    _op_mba_compute,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _indexed_address_asm,
    _mem_address_asm,
)
from tests.utils.assertions import expect

_MASK64 = (1 << 64) - 1
_BOOLEAN_OPS = (
    ("xor", lambda a, b: a ^ b),
    ("and", lambda a, b: a & b),
    ("or", lambda a, b: a | b),
)

# Edge cases plus a deterministic spread of random 64-bit inputs, including the
# a == b diagonal, so every template is exercised against carries, the high bit,
# all-ones and all-zeros operands.
_EDGE_VALUES = (0x0, _MASK64, 0x1, 1 << 63, (1 << 63) - 1, 0xDEADBEEFCAFEB0BA)


def _sample_pairs() -> tuple[tuple[int, int], ...]:
    pairs = [(a, b) for a in _EDGE_VALUES for b in _EDGE_VALUES]
    pairs.extend((value, value) for value in _EDGE_VALUES)
    rng = randomness.Random(0xC0FFEE)
    pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(128))
    return tuple(pairs)


_SAMPLE_PAIRS = _sample_pairs()


def test_no_address_prologue_uses_a_literal_add() -> None:
    for key in range(1, 256):
        for asm in (
            _mem_address_asm(False, key, "0x6c6c6c6c")[0],
            _mem_address_asm(True, key, "0x6c6c6c6c")[0],
            _indexed_address_asm(key, "0x6c6c6c6c")[0],
        ):
            expect("add r10, rax" not in asm)
            expect("add r10, qword ptr [rsp+r9*8]" not in asm)


def test_displacement_fold_is_one_of_the_known_mba_variants() -> None:
    for key in range(1, 256):
        expect(_mba_add_r10_rax(key) == _mba_add("rax", "rcx", key))
        expect(not (_mba_add("rax", "rcx", key) not in {t.format(a="rax", t="rcx") for t in _MBA_ADD_TEMPLATES}))


def test_mba_variant_is_polymorphic_across_instances() -> None:
    # Different bytecode keys must be able to select different folds, so the MBA
    # is not a single fixed pattern across samples.
    produced = {_mba_add_r10_rax(key) for key in range(1, 256)}
    expect(len(produced) == len(_MBA_ADD_TEMPLATES) > 1)


def test_boolean_mba_never_contains_the_literal_native_op() -> None:
    # The handler for op X must not contain the plain `X r10, rax` it stands for.
    # Match the whole indented instruction so `or` does not falsely hit `xor`.
    for mnemonic, _ in _BOOLEAN_OPS:
        for key in range(1, 256):
            expect(f"  {mnemonic} r10, rax\n" not in _op_mba_compute(mnemonic, key))


def test_boolean_mba_is_polymorphic_across_instances() -> None:
    # Every equivalent rewrite in a pool must be reachable across bytecode keys, so
    # the boolean handler is not a single fixed MBA signature across samples.
    for mnemonic, _ in _BOOLEAN_OPS:
        produced = {_op_mba_compute(mnemonic, key) for key in range(1, 256)}
        expect(len(produced) == len(_BOOL_VARIANTS[mnemonic]) > 1)


def _emulate(asm: str, operand_reg: int, a: int, b: int) -> tuple[int, int]:
    """Assemble ``asm`` and run it with r10 = a and ``operand_reg`` = b.

    Returns the post-execution ``(r10, operand_reg)`` so a caller can assert both
    the computed value and that the operand register was preserved.
    """
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    u_c__x86__r_e_g__r10 = importlib.import_module("unicorn.x86_const").UC_X86_REG_R10

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    mu.reg_write(u_c__x86__r_e_g__r10, a)
    mu.reg_write(operand_reg, b)
    mu.emu_start(0x1000, 0x1000 + len(code))
    return mu.reg_read(u_c__x86__r_e_g__r10), mu.reg_read(operand_reg)


@pytest.mark.parametrize("template_index", range(len(_MBA_ADD_TEMPLATES)))
def test_every_add_template_computes_r10_plus_addend_and_keeps_the_addend(
    template_index: int,
) -> None:
    # a == r10, b == addend (rbx); the fold must leave r10 = a + b and rbx = b.
    pytest.importorskip("unicorn")
    u_c__x86__r_e_g__r_b_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RBX

    asm = _MBA_ADD_TEMPLATES[template_index].format(a="rbx", t="rcx")
    for value_a, value_b in _SAMPLE_PAIRS:
        result = _emulate(asm, u_c__x86__r_e_g__r_b_x, value_a, value_b)
        expect(result == (value_a + value_b & _MASK64, value_b))


_BOOL_CASES = tuple(
    (mnemonic, native, index) for mnemonic, native in _BOOLEAN_OPS for index in range(len(_BOOL_VARIANTS[mnemonic]))
)


@pytest.mark.parametrize("mnemonic,native,variant_index", _BOOL_CASES)
def test_every_boolean_variant_computes_the_native_op_and_keeps_rax(mnemonic: str, native, variant_index: int) -> None:
    # a == r10, b == rax; each rewrite must leave r10 = a <op> b and rax = b.
    pytest.importorskip("unicorn")
    u_c__x86__r_e_g__r_a_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RAX

    asm = _BOOL_VARIANTS[mnemonic][variant_index]
    for value_a, value_b in _SAMPLE_PAIRS:
        result = _emulate(asm, u_c__x86__r_e_g__r_a_x, value_a, value_b)
        expect(result == (native(value_a, value_b) & _MASK64, value_b))
