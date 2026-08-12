"""The shift flag-capture ISA family (shift_variant) is bit-exact vs the CPU.

The canonical capture pushes the whole RFLAGS after a native shift; the alternate
reconstructs the readable condition flags with lahf + seto. Both read the *real*
CPU flags, so for every (mnemonic, width, count, value) - including the
architecturally-undefined OF at count > 1 and the count-masked-to-zero no-op - the
reconstructed image must carry the same CF/PF/ZF/SF/OF bits the jcc handlers read
as the canonical pushfq. This runs the two idioms under Unicorn and compares the
reader bits directly (no mocks, real emulation).
"""

from __future__ import annotations

from contextlib import suppress

import keystone
import unicorn
from unicorn import x86_const

from r2morph.mutations.code_virtualization_region_isa import build_isa_spec
from r2morph.mutations.code_virtualization_region_shift import SHIFT_VARIANT_BITS, shift_flag_capture_asm

_FLAGS_OFF = 0x40
_STACK_BASE = 0x300000
_STACK_SIZE = 0x10000
_RSP = 0x308000
_CODE_BASE = 0x400000

# The RFLAGS bits any jcc handler reads: CF(0), PF(2), ZF(6), SF(7), OF(11).
_READER_MASK = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11)

_MNEMONICS = ("shl", "shr", "sar")
_COUNTS = (0, 1, 2, 16, 31, 32, 63)
_VALUES = (
    0x0,
    0x1,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000,
    0xAAAAAAAAAAAAAAAA,
    0x0123456789ABCDEF,
)


def _run(mnemonic: str, width: int, count: int, value: int, variant: int) -> tuple[int, int]:
    """Assemble ``{mnemonic} <reg>, cl`` + the capture idiom, run it, and return the
    (reader-masked flag image, shifted result) the capture leaves behind."""
    reg = "rax" if width == 64 else "eax"
    masked_value = value & (0xFFFFFFFFFFFFFFFF if width == 64 else 0xFFFFFFFF)
    asm = (
        f"  mov rax, {hex(masked_value)}\n"
        f"  mov ecx, {count}\n"
        f"  {mnemonic} {reg}, cl\n" + shift_flag_capture_asm(variant, _FLAGS_OFF) + "  hlt\n"
    )
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, addr=_CODE_BASE, as_bytes=True)

    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(_CODE_BASE, 0x1000)
    uc.mem_map(_STACK_BASE, _STACK_SIZE)
    uc.mem_write(_CODE_BASE, code)
    uc.reg_write(x86_const.UC_X86_REG_RSP, _RSP)
    with suppress(unicorn.UcError):
        uc.emu_start(_CODE_BASE, _CODE_BASE + len(code))
    stored = int.from_bytes(uc.mem_read(_RSP + _FLAGS_OFF, 8), "little")
    result = uc.reg_read(x86_const.UC_X86_REG_RAX)
    return stored & _READER_MASK, result


def test_shift_capture_variant_matches_pushfq_reader_bits() -> None:
    for variant in range(1, 1 << SHIFT_VARIANT_BITS):
        for mnemonic in _MNEMONICS:
            for width in (32, 64):
                for count in _COUNTS:
                    for value in _VALUES:
                        base_flags, base_result = _run(mnemonic, width, count, value, 0)
                        alt_flags, alt_result = _run(mnemonic, width, count, value, variant)
                        assert alt_flags == base_flags, (mnemonic, width, count, hex(value), variant)
                        assert alt_result == base_result, (mnemonic, width, count, hex(value), variant)


def test_shift_variant_zero_is_the_canonical_pushfq_spelling() -> None:
    assert shift_flag_capture_asm(0, _FLAGS_OFF) == f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFF}]\n"


def test_shift_variant_alternate_differs_from_canonical() -> None:
    assert shift_flag_capture_asm(1, _FLAGS_OFF) != shift_flag_capture_asm(0, _FLAGS_OFF)
    assert "lahf" in shift_flag_capture_asm(1, _FLAGS_OFF)
    assert "pushfq" not in shift_flag_capture_asm(1, _FLAGS_OFF)


def test_build_isa_spec_canonical_shift_variant_is_zero() -> None:
    assert build_isa_spec(0).shift_variant == 0


def test_build_isa_spec_selects_the_alternate_shift_variant_for_some_seed() -> None:
    variants = {build_isa_spec(seed).shift_variant for seed in range(1, 400)}
    assert variants == set(range(1 << SHIFT_VARIANT_BITS))
