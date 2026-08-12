"""
Bit-exact equivalence of every per-build compare spelling against the CPU.

``code_virtualization_region_compare.compare_compute`` spells the comparison value
(``a - b`` for cmp, ``a & b`` for test) several algebraically-equivalent ways,
selected per build by ``compare_variant`` and composed with the arithmetic fold.
The handlers feed that value into the hand-built flag synthesis, so a wrong
spelling would silently corrupt a downstream conditional branch. This harness pins
every spelling: for representative variants, ops, widths and edge-case operands it
runs the full ``compare_compute`` + ``synth_flags_asm`` and compares the covered
flag bits against a real ``cmp``/``test``, both emulated with unicorn. It also
proves ``compare_variant`` 0 keeps the handlers' inline canonical form and that
distinct isa_seeds diverge.
"""

from __future__ import annotations

import pytest

from r2morph.mutations.code_virtualization_region_compare import compare_compute
from r2morph.mutations.code_virtualization_region_flags import synth_flags_asm
from r2morph.mutations.code_virtualization_region_handlers import IntegerHandlerConfig, _compare_handler_asm
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec

_MASK = {32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}
_ZF, _SF, _CF, _OF, _PF = 1 << 6, 1 << 7, 1 << 0, 1 << 11, 1 << 2
# cmp drives all five; test clears CF and OF (logic), so they are covered too.
_COVERED = _ZF | _SF | _PF | _CF | _OF
# op -> (synth mode, python reference for the compared value).
_REF = {
    "cmp": ("sub", lambda a, b, m: (a - b) & m),
    "test": ("logic", lambda a, b, m: (a & b) & m),
}

# compare_variant values covering both cmp choices (v % 3) and test choices
# (v // 3 % 2); arith_variant values compose the inner fold diversity.
_COMPARE_VARIANTS = (0, 1, 2, 3, 4, 5)
_ARITH_VARIANTS = (0, 0x555)
_KEY = 0x5B


def _edge_operands(width: int) -> tuple[int, ...]:
    mask = _MASK[width]
    sign = 1 << (width - 1)
    fixed = (0, 1, 2, mask, sign, sign - 1, sign + 1, mask - 1)
    import random

    rng = random.Random(0xC0FFEE01)
    extra = tuple(rng.randrange(1 << width) for _ in range(6))
    return fixed + extra


def _run(asm: str, reg_in: dict[int, int], reg_out: list[int]) -> dict[int, int]:
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_RSP

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    mu.mem_map(0x200000, 0x2000)
    mu.reg_write(UC_X86_REG_RSP, 0x201000)
    for reg, value in reg_in.items():
        mu.reg_write(reg, value)
    mu.emu_start(0x1000, 0x1000 + len(code))
    return {reg: mu.reg_read(reg) for reg in reg_out}


def _regs() -> tuple[int, int, int, int]:
    from unicorn.x86_const import UC_X86_REG_R11, UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX

    return UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R11


def _cpu_flags(op: str, width: int, a: int, b: int) -> int:
    """The real RFLAGS of ``a cmp/test b`` at ``width``, via unicorn."""
    from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX

    reg = {32: ("eax", "ecx"), 64: ("rax", "rcx")}[width]
    asm = f"  {op} {reg[0]}, {reg[1]}\n  pushfq\n  pop rdx\n"
    out = _run(asm, {UC_X86_REG_RAX: a, UC_X86_REG_RCX: b}, [UC_X86_REG_RDX])
    return out[UC_X86_REG_RDX]


def _compare_flags(op: str, width: int, arith_variant: int, compare_variant: int, a: int, b: int) -> int:
    """RFLAGS from the full per-build compare computation + flag synthesis."""
    rax, rbx, rbp, r11 = _regs()
    mode = _REF[op][0]
    # Contract: entry rbx=a, rbp=b, rax=b -> compare_compute leaves r10=result.
    asm = compare_compute(op, _KEY, arith_variant, compare_variant)
    if width == 32:
        asm += "  mov r10d, r10d\n"
    asm += synth_flags_asm(width, mode, 0)
    out = _run(asm, {rbx: a, rbp: b, rax: b}, [r11])
    return out[r11]


@pytest.mark.parametrize("op", ("cmp", "test"))
@pytest.mark.parametrize("width", (32, 64))
@pytest.mark.parametrize("compare_variant", _COMPARE_VARIANTS)
@pytest.mark.parametrize("arith_variant", _ARITH_VARIANTS)
def test_compare_flags_match_the_cpu_for_every_variant(
    op: str, width: int, compare_variant: int, arith_variant: int
) -> None:
    pytest.importorskip("keystone")
    pytest.importorskip("unicorn")
    native = "cmp" if op == "cmp" else "test"
    for a in _edge_operands(width):
        for b in _edge_operands(width):
            expected = _cpu_flags(native, width, a, b) & _COVERED
            got = _compare_flags(op, width, arith_variant, compare_variant, a, b) & _COVERED
            assert (
                got == expected
            ), f"{op} w{width} cv{compare_variant} av{arith_variant} a={a:#x} b={b:#x}: {got:#x} != {expected:#x}"


def test_compare_variant_zero_keeps_the_inline_canonical_handler() -> None:
    canonical = _compare_handler_asm(IntegerHandlerConfig("cmp_r_64", _KEY, "0x0", "0x0"))
    nonzero = _compare_handler_asm(IntegerHandlerConfig("cmp_r_64", _KEY, "0x0", "0x0", compare_variant=1))
    # The +1-fold spelling is unique to a non-canonical build; variant 0 must not use it.
    assert "lea r10, [r10 + 1]" not in canonical
    assert nonzero != canonical


def test_isa_spec_zero_seed_is_canonical_and_seeds_diverge() -> None:
    assert build_isa_spec(0).compare_variant == 0
    variants = {build_isa_spec(seed).compare_variant for seed in range(1, 300)}
    assert len(variants) > 1
