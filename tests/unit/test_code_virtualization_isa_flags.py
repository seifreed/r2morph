"""
Bit-exact equivalence of every per-build flag-synthesis spelling against the CPU.

``code_virtualization_region_flags.synth_flags_asm`` builds a RFLAGS image by hand
so a handler never spells out a flag-setting native op. Each of ZF/SF/CF/OF/PF has a
canonical spelling and one algebraically-equivalent alternate, selected per build by
``flag_variant``. A wrong alternate would silently corrupt a downstream conditional
branch - the exit-code tests would not necessarily catch it - so this harness pins
every spelling: for representative variants, modes, widths and edge-case operands it
compares the synthesized bits against the flags a real ``add``/``sub``/``and``/``or``/
``xor`` sets, both emulated with unicorn. It also proves ``flag_variant`` 0 is
byte-identical to the canonical output and that distinct isa_seeds diverge.
"""

from __future__ import annotations

import importlib

import pytest

from r2morph.mutations.code_virtualization_region_flags import FLAG_VARIANT_BITS, synth_flags_asm
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec
from tests.utils.assertions import expect

_EXPECTED_WIDTH_64 = 64
_EXPECTED_WIDTH_64_2 = 64


_MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}
# The flag bits synth_flags_asm builds (AF is deliberately omitted).
_ZF, _SF, _CF, _OF, _PF = 1 << 6, 1 << 7, 1 << 0, 1 << 11, 1 << 2
_COVERED = {
    "add": _ZF | _SF | _PF | _CF | _OF,
    "sub": _ZF | _SF | _PF | _CF | _OF,
    "logic": _ZF | _SF | _PF | _CF | _OF,  # logic must also drive CF=OF=0
}
# mode -> (native mnemonic, python reference) for the ground-truth op.
_NATIVE = {
    "add": ("add", lambda a, b, m: (a + b) & m),
    "sub": ("sub", lambda a, b, m: (a - b) & m),
    "and": ("and", lambda a, b, m: (a & b) & m),
    "or": ("or", lambda a, b, m: (a | b) & m),
    "xor": ("xor", lambda a, b, m: (a ^ b) & m),
}
# Native mnemonic -> the synth mode it drives.
_MODE = {"add": "add", "sub": "sub", "and": "logic", "or": "logic", "xor": "logic"}

# Variants exercising each flag's alternate in isolation (single set bit), none
# (0 = canonical), all (2**bits - 1), and two mixed selections.
_ALL = (1 << FLAG_VARIANT_BITS) - 1
_VARIANTS = (0, 1, 2, 4, 8, 16, _ALL, 0b10101, 0b01010)


def _edge_operands(width: int) -> tuple[int, ...]:
    mask = _MASK[width]
    sign = 1 << (width - 1)
    fixed = (0, 1, 2, mask, sign, sign - 1, sign + 1, mask - 1)
    # Deterministic pseudo-random values (constant seed, never runtime randomness).
    randomness = importlib.import_module("r2morph.core").randomness

    rng = randomness.Random(0xF1A65EED)
    extra = tuple(rng.randrange(1 << width) for _ in range(6))
    return fixed + extra


def _run(asm: str, reg_in: dict[int, int], reg_out: list[int]) -> dict[int, int]:
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    u_c__x86__r_e_g__r_s_p = importlib.import_module("unicorn.x86_const").UC_X86_REG_RSP

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm, 0x1000)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes(code))
    mu.mem_map(0x200000, 0x2000)
    mu.reg_write(u_c__x86__r_e_g__r_s_p, 0x201000)
    for reg, value in reg_in.items():
        mu.reg_write(reg, value)
    mu.emu_start(0x1000, 0x1000 + len(code))
    return {reg: mu.reg_read(reg) for reg in reg_out}


# unicorn register ids, imported lazily so the module imports without unicorn.
def _regs() -> tuple[int, int, int, int, int]:
    u_c__x86__r_e_g__r10 = importlib.import_module("unicorn.x86_const").UC_X86_REG_R10
    u_c__x86__r_e_g__r11 = importlib.import_module("unicorn.x86_const").UC_X86_REG_R11
    u_c__x86__r_e_g__r_a_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RAX
    u_c__x86__r_e_g__r_b_p = importlib.import_module("unicorn.x86_const").UC_X86_REG_RBP
    u_c__x86__r_e_g__r_b_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RBX

    return (
        u_c__x86__r_e_g__r_a_x,
        u_c__x86__r_e_g__r_b_x,
        u_c__x86__r_e_g__r_b_p,
        u_c__x86__r_e_g__r10,
        u_c__x86__r_e_g__r11,
    )


def _cpu_flags(mnemonic: str, width: int, a: int, b: int) -> int:
    """The real RFLAGS of ``a <mnemonic> b`` at ``width``, via unicorn."""
    rax, _rbx, _rbp, _r10, _r11 = _regs()
    u_c__x86__r_e_g__r_c_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RCX
    u_c__x86__r_e_g__r_d_x = importlib.import_module("unicorn.x86_const").UC_X86_REG_RDX

    reg = {8: ("al", "cl"), 16: ("ax", "cx"), 32: ("eax", "ecx"), 64: ("rax", "rcx")}[width]
    asm = f"  {mnemonic} {reg[0]}, {reg[1]}\n  pushfq\n  pop rdx\n"
    out = _run(asm, {rax: a, u_c__x86__r_e_g__r_c_x: b}, [u_c__x86__r_e_g__r_d_x])
    return out[u_c__x86__r_e_g__r_d_x]


def _synth_flags(*values: int | str) -> int:
    """The RFLAGS image synth_flags_asm builds for these operands, via unicorn."""
    mode, width, variant, a, b, result = values
    _rax, rbx, rbp, r10, r11 = _regs()
    asm = synth_flags_asm(width, mode, variant)
    out = _run(asm, {rbx: a, rbp: b, r10: result}, [r11])
    return out[r11]


@pytest.mark.parametrize("mnemonic", sorted(_NATIVE))
@pytest.mark.parametrize("width", (8, 16, 32, 64))
@pytest.mark.parametrize("variant", _VARIANTS)
def test_synthesized_flags_match_the_cpu_for_every_variant(mnemonic: str, width: int, variant: int) -> None:
    pytest.importorskip("keystone")
    pytest.importorskip("unicorn")
    native, ref = _NATIVE[mnemonic]
    mode = _MODE[mnemonic]
    covered = _COVERED[mode]
    mask = _MASK[width]
    for a in _edge_operands(width):
        for b in _edge_operands(width):
            result = ref(a, b, mask)
            expected = _cpu_flags(native, width, a, b) & covered
            got = _synth_flags(mode, width, variant, a, b, result) & covered
            expect(got == expected, f"{mnemonic} w{width} v{variant} a={a:#x} b={b:#x}: {got:#x} != {expected:#x}")


@pytest.mark.parametrize("width", (32, 64))
@pytest.mark.parametrize("mode", ("add", "sub", "logic"))
def test_flag_variant_zero_is_the_canonical_spelling(width: int, mode: str) -> None:
    # The canonical spelling is exactly what the pre-feature single builder emitted.
    a, b, r = ("rbx", "rbp", "r10") if width == _EXPECTED_WIDTH_64 else ("ebx", "ebp", "r10d")
    c, t, u = ("rcx", "rax", "r9") if width == _EXPECTED_WIDTH_64_2 else ("ecx", "eax", "r9d")
    sh = width - 1
    lines = ["  xor r11d, r11d\n"]
    lines.append(
        f"  mov {c}, {r}\n  neg {c}\n  or {c}, {r}\n  shr {c}, {sh}\n"
        f"  and {c}, 1\n  xor {c}, 1\n  shl {c}, 6\n  or r11, rcx\n"
    )
    lines.append(f"  mov {c}, {r}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 7\n  or r11, rcx\n")
    if mode == "add":
        lines.append(
            f"  mov {c}, {a}\n  and {c}, {b}\n  mov {u}, {a}\n  or {u}, {b}\n"
            f"  mov {t}, {r}\n  not {t}\n  and {u}, {t}\n  or {c}, {u}\n"
            f"  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
        lines.append(
            f"  mov {c}, {a}\n  xor {c}, {r}\n  mov {u}, {b}\n  xor {u}, {r}\n"
            f"  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    elif mode == "sub":
        lines.append(
            f"  mov {c}, {a}\n  not {c}\n  and {c}, {b}\n  mov {u}, {a}\n"
            f"  not {u}\n  or {u}, {b}\n  and {u}, {r}\n  or {c}, {u}\n"
            f"  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
        lines.append(
            f"  mov {c}, {a}\n  xor {c}, {b}\n  mov {u}, {a}\n  xor {u}, {r}\n"
            f"  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    lines.append(
        f"  movzx ecx, r10b\n  mov {u}, {c}\n  shr {u}, 4\n  xor {c}, {u}\n"
        f"  mov {u}, {c}\n  shr {u}, 2\n  xor {c}, {u}\n  mov {u}, {c}\n"
        f"  shr {u}, 1\n  xor {c}, {u}\n  not {c}\n  and ecx, 1\n  shl ecx, 2\n  or r11, rcx\n"
    )
    expect(synth_flags_asm(width, mode, 0) == "".join(lines))


def test_flag_variants_produce_distinct_assembly() -> None:
    # A build with a nonzero personality must not render the canonical flag synthesis.
    for width in (32, 64):
        for mode in ("add", "sub", "logic"):
            canonical = synth_flags_asm(width, mode, 0)
            expect(synth_flags_asm(width, mode, _ALL) != canonical)


def test_isa_spec_zero_seed_is_canonical_and_seeds_diverge() -> None:
    expect(build_isa_spec(0).flag_variant == 0)
    variants = {build_isa_spec(seed).flag_variant for seed in range(1, 200)}
    # A byte over 200 seeds must exercise more than one personality.
    expect(not (len(variants) <= 1))
